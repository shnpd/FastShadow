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

// FilterTransByInputaddr 根据输入地址筛选交易，默认一个地址只参与一个交易(本方法只在simnet网络中使用，在实际mainnet中可以直接调用第三方api筛选交易)
func FilterTransByInputaddr(client *rpcclient.Client, addr string) (*chainhash.Hash, error) {
	transactions, _ := client.ListTransactionsCount("*", 99999)
	// 遍历所有交易依次筛选
	for _, v := range transactions {
		txId, err := chainhash.NewHashFromStr(v.TxID)
		// coinbase交易没有输入
		if v.Generated {
			continue
		}
		// 获取交易的输入地址
		inputAddr, err := getTransInAddr(client, txId)
		if inputAddr == addr {
			return txId, err
		}
	}
	return nil, fmt.Errorf("not exist transaction with input address:%s", addr)
}

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
