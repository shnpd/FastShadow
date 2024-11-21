package Transaction

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"strconv"
)

// EntireSendTrans 完整交易发送，包括交易生成、交易签名、交易广播，最终返回广播的交易id
func EntireSendTrans(client *rpcclient.Client, sourceAddr, destAddr string, amount int64, embedMsg *string) (*chainhash.Hash, error) {
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
	for _, utxo := range utxos {
		if utxo.Address == sourceAddr {
			sourceUTXO = utxo
			break
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
func SignTrans(client *rpcclient.Client, rawTx *wire.MsgTx, embedMsg *string) (*wire.MsgTx, error) {
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

// getInputUTXO 获取交易的输入UTXO
func getInputUTXO(client *rpcclient.Client, txid *chainhash.Hash) ([]wire.OutPoint, error) {
	// 根据交易id筛选原始交易（原始交易包含txin字段）
	rawTransaction, err := client.GetRawTransaction(txid)
	if err != nil {
		return nil, err
	}
	txInput := rawTransaction.MsgTx().TxIn
	var inputUtxo []wire.OutPoint
	for _, v := range txInput {
		inputUtxo = append(inputUtxo, v.PreviousOutPoint)
	}
	return inputUtxo, nil
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

// TODO:可优化
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
		// 获取交易的输入
		inputUTXO, err := getInputUTXO(client, txId)
		if err != nil {
			return nil, err
		}
		// 根据输入utxo提取输入地址
		for _, utxo := range inputUTXO {
			// 产生这个utxo的交易id
			utxoHash := utxo.Hash
			// utxo在交易中的序号
			utxoIndex := utxo.Index
			// 获取前置交易
			previousTrans, _ := client.GetTransaction(&utxoHash)
			var addrTemp string
			// 从details找到对应的vout，（每一个输出都会在details中插入两条记录，一个send类型，一个receive类型，coinbase交易只有一个为generate类型）
			if previousTrans.Details[0].Category == "generate" {
				continue
			}
			addrTemp = previousTrans.Details[2*utxoIndex+1].Address
			// 交易的输入地址包含目标地址
			if err != nil {
				return nil, err
			}
			if addrTemp == addr {
				return txId, nil
			}
		}
	}
	return nil, fmt.Errorf("not exist transaction with input address:%s", addr)
}
