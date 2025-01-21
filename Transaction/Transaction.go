package Transaction

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"log"
	"net/http"
	"strconv"
)

// GetSigFromTx 从交易id查询交易签名
func GetSigFromTx(client *rpcclient.Client, txid *chainhash.Hash) string {
	rawtx, err := client.GetRawTransaction(txid)
	if err != nil {
		log.Fatal(err)
	}
	sigScript := hex.EncodeToString(rawtx.MsgTx().TxIn[0].SignatureScript)
	sigScript = sigScript[2:]
	length := sigScript[2:4]
	lenSig, _ := strconv.ParseInt(length, 16, 10)
	sigScript = sigScript[0 : 4+lenSig*2]
	return sigScript
}

// EntireSendTrans 完整交易发送，包括交易生成、交易签名、交易广播，最终返回广播的交易id
func EntireSendTrans(client *rpcclient.Client, sourceAddr, destAddr string, amount int64, embedMsg *[]byte) (*chainhash.Hash, error) {
	rawTx, err := GenerateTrans(client, sourceAddr, destAddr, amount)
	if err != nil {
		return nil, err
	}
	signTx, err := SignTrans(client, rawTx, embedMsg)
	if err != nil {
		return nil, err
	}
	transId, err := BroadTrans(client, signTx)
	if err != nil {
		return nil, err
	}
	return transId, nil
}

// GenerateTrans 生成sourceAddr到destAddr的原始交易
func GenerateTrans(client *rpcclient.Client, sourceAddr, destAddr string, amount int64) (*wire.MsgTx, error) {
	// 筛选源地址的UTXO
	utxos, _ := client.ListUnspent()
	var sourceUTXO btcjson.ListUnspentResult
	for i, utxo := range utxos {
		if utxo.Address == sourceAddr {
			sourceUTXO = utxo
			break
		}
		if i == len(utxos)-1 {
			return nil, fmt.Errorf("UTXO not found")
		}
	}

	// 构造输入
	var inputs []btcjson.TransactionInput
	inputs = append(inputs, btcjson.TransactionInput{
		Txid: sourceUTXO.TxID,
		Vout: sourceUTXO.Vout,
	})
	//	构造输出
	outAddr, err := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	if err != nil {
		return nil, err
	}
	outputs := map[btcutil.Address]btcutil.Amount{
		// 0.1BTC的手续费
		outAddr: btcutil.Amount((sourceUTXO.Amount - 0.1) * 1e8),
	}
	//	创建交易
	rawTx, err := client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateRawTransaction error:%s", err)
	}
	return rawTx, nil
}

// SignTrans 签名交易，嵌入秘密消息，并保存特殊q
func SignTrans(client *rpcclient.Client, rawTx *wire.MsgTx, embedMsg *[]byte) (*wire.MsgTx, error) {
	signedTx, complete, err, _ := client.SignRawTransaction(rawTx, embedMsg)
	if err != nil {
		return nil, fmt.Errorf("error signing transaction: %v", err)
	}
	if !complete {
		return nil, fmt.Errorf("transaction signing incomplete")
	}

	return signedTx, nil
}

// BroadTrans 广播交易
func BroadTrans(client *rpcclient.Client, signedTx *wire.MsgTx) (*chainhash.Hash, error) {
	txHash, err := client.SendRawTransaction(signedTx, false)
	if err != nil {
		return nil, fmt.Errorf("SendRawTransaction error: %v", err)
	}
	return txHash, nil
}

// GetHashFromTx 提取计算交易签名的原始数据
func GetHashFromTx(client *rpcclient.Client, rawTx *btcutil.Tx) ([]byte, error) {
	var script []byte
	var hashType txscript.SigHashType
	tx := new(wire.MsgTx)
	var idx int
	idx = 0
	tx = rawTx.MsgTx()
	hashType = 1
	script = getScript(client, rawTx.MsgTx())
	hash, err := txscript.CalcSignatureHash(script, hashType, tx, idx)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// getScript 获取输入交易的前置交易的输出脚本
func getScript(client *rpcclient.Client, tx *wire.MsgTx) []byte {
	txHash := tx.TxIn[0].PreviousOutPoint.Hash
	rawTx, _ := client.GetRawTransaction(&txHash)
	script := rawTx.MsgTx().TxOut[0].PkScript
	return script
}

// GetSignaruteFromTx 提取输入原始交易的签名
func GetSignaruteFromTx(rawTx *btcutil.Tx) *ecdsa.Signature {
	signatureScript := hex.EncodeToString(rawTx.MsgTx().TxIn[0].SignatureScript)
	sig := GetSigFromHex(signatureScript)
	r := sig.R()
	s := sig.S()
	//if Share.IsTxSignOver[*rawTx.Hash()] {
	//	s.Negate()
	//}
	sigOrigin := ecdsa.NewSignature(&r, &s)
	return sigOrigin
}

// GetSigFromHex 从Hex字段提取签名
func GetSigFromHex(HexSig string) *ecdsa.Signature {
	lenSigByte := HexSig[4:6]
	t, _ := strconv.ParseInt(lenSigByte, 16, 0)
	sigStr := HexSig[2 : 6+2*t]
	//解码
	asmByte, _ := hex.DecodeString(sigStr)
	sig, _ := ecdsa.ParseDERSignature(asmByte)
	return sig
}

// 获取交易的输入地址
func getTransInAddr(client *rpcclient.Client, txHash *chainhash.Hash) (string, error) {
	txDetails, err := client.GetRawTransactionVerbose(txHash)
	if err != nil {
		return "", err
	}
	for _, vin := range txDetails.Vin {
		prevTxid := vin.Txid
		if prevTxid == "" {
			return "", errors.New("not exist input address")
		}
		voutIndex := vin.Vout
		// 查询前一个交易的输出
		hash, _ := chainhash.NewHashFromStr(prevTxid)
		prevTx, err := client.GetRawTransactionVerbose(hash)
		if err != nil {
			return "", fmt.Errorf("error fetching previous transaction: %v", err)
		}
		// 获取指定输出的地址
		vout := prevTx.Vout[voutIndex]
		address := vout.ScriptPubKey.Address
		if address != "" {
			return address, nil
		}
	}
	return "", errors.New("get input address error")
}

// FilterTransByInputaddr 根据输入地址筛选交易，默认一个地址只参与一个交易(本方法只在simnet网络中使用，在实际mainnet中可以直接调用第三方api筛选交易)
func FilterTransByInputaddr(client *rpcclient.Client, addr btcutil.Address) (*chainhash.Hash, error) {
	address, err := btcutil.DecodeAddress("16mDJ7EEBjWvyJNX9oyaFS9fMVDjHTJfLZ", &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	tx, err := client.SearchRawTransactions(address, 0, 1, true, nil)
	if err != nil {
		return nil, err
	}
	txid, err := chainhash.NewHashFromStr(tx[0].TxID())
	if err != nil {
		return nil, err
	}
	return txid, nil
}

// filterTransByInputaddrByAPI 模拟主网查询请求，任意发送一个地址的请求，直接返回隐蔽交易的id（本地simnet网络无法调用第三方api）
func FilterTransByInputaddrByAPI(client *rpcclient.Client, addr string) (*chainhash.Hash, error) {
	url := fmt.Sprintf("https://api.3xpl.com/bitcoin/address/%s?token=3A0_t3st3xplor3rpub11cb3t4efcd21748a5e&data=events", addr)
	resp, err := http.Get(url)
	if resp.StatusCode != 200 {
		log.Fatalf("请求失败：%s", resp.Status)
		return nil, err
	}
	defer resp.Body.Close()
	// 模拟由api返回交易id
	switch addr {
	case "SRMMzEu1AtnTfQorrE1CAiTQ2AdVgfiwp6":
		hash, _ := chainhash.NewHashFromStr("bfa8d8dac0eb0d7c06feb5e88272edabf882488e9e90d1e6ca901901e3cb7647")
		return hash, nil
	case "SiGGuKwQ2WP1uZ63TBVk1E6mb3qPyqrnEg":
		hash, _ := chainhash.NewHashFromStr("6187c54d900a6ae37568b2c33b80d764af50cb1c2fb13b4ab24366f5cbb25432")
		return hash, nil
	case "SNb2cVFfzTW4ecMyRg7DncL4vKbFka9mGA":
		hash, _ := chainhash.NewHashFromStr("d570c837b2f6b90e4116985f63a6c11aa385945903517f8f68ad834c80d2ccb8")
		return hash, nil
	case "SjJaJhDBcWUW2x8UUiXrucpqZMW4GfEbFn":
		hash, _ := chainhash.NewHashFromStr("a2ce12b44edac96c9a5b5b3f5c68d61880281c08ce1dc75a933f45b5ae3d242f")
		return hash, nil
	case "STGeYnmKs1XRRUdY5xBWQgkDe12XM69uPR":
		hash, _ := chainhash.NewHashFromStr("4e9e70c5592a2a800f27d7a50c8474e38c326c3433d0ce479d369b43de4513ec")
		return hash, nil
	case "SZKehtZnRaRD9xX3TWzPaJ1noWJPewsvbz":
		hash, _ := chainhash.NewHashFromStr("eb8c5843d1c3acace9ddd046a96e0f4183f89a1ca186d8e806a83c26a52120a8")
		return hash, nil
	case "Sbw2ujZf3zPw1xqKEFdKsYnfCKWZLodjHn":
		hash, _ := chainhash.NewHashFromStr("a55d7f5b10a600dff9f431acb07716ded950ba10a470678cc689cb3174e7b008")
		return hash, nil
	case "ScnZkmpzFhkTqDggW58ngUrBZQ6kz6Yx5Y":
		hash, _ := chainhash.NewHashFromStr("1df500db9adbfb1b806abe3f5e7c883e7553e48b8c8fa5d9058e4479b79b598b")
		return hash, nil
	case "SkcyqqePBo4YBPbkm3HsFXuCXnmK9XmVCj":
		hash, _ := chainhash.NewHashFromStr("e671bb55faa4bd5b3979ffef172a982dfec17902b0e0dbc8de4448c008f39add")
		return hash, nil
	case "ScECtJUTBteEKBh8s5ZNZkeUa6Rutz9vK8":
		hash, _ := chainhash.NewHashFromStr("88022519083fee764f6c737bfdc704f372caf48223d4a5094c5ae118f9ce8079")
		return hash, nil
	case "SS6TEYptYhuDDwPvJEtbfYRdPGVxNKEDY9":
		hash, _ := chainhash.NewHashFromStr("1ff3be006e37cb1962956d9a9ae0ec8ea1c2fe75f3e114b6e7c153e7a34cebd4")
		return hash, nil
	case "Sft65bpbVnAoBYN3d78YXr2pHHVRjYDmdv":
		hash, _ := chainhash.NewHashFromStr("9630ba724859685d19852d9b6e84892dff64c098990796e017716d6b06efc09b")
		return hash, nil
	case "Sc4DW59hYDmyz8ZNZZdR7wSNkZt99XrydU":
		hash, _ := chainhash.NewHashFromStr("1a2134cb448864b232fc00d3e954fb0b845a90cb36fe8be8d749a6d89571401b")
		return hash, nil
	}
	return nil, errors.New("can't get trans by input address")
}
