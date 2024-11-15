package main

import (
	"covertCommunication/KeyDerivation"
	"covertCommunication/Share"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type CovertMsgTx struct {
	msgtx   *wire.MsgTx
	isSOver []bool
}

// 生成sourceAddr到destAddr的原始交易（将UTXO全部转给目标地址，没有交易费）
func GenerateTrans(sourceAddr, destAddr string) (*CovertMsgTx, error) {
	// 构造输入
	var inputs []btcjson.TransactionInput
	if len(UTXObyAddress[sourceAddr]) == 0 {
		return nil, fmt.Errorf("%s have not UTXO", sourceAddr)
	}
	utxo := UTXObyAddress[sourceAddr][0]
	inputs = append(inputs, btcjson.TransactionInput{
		Txid: utxo.TxID,
		Vout: utxo.Vout,
	})
	//	构造输出
	outAddr, err := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	if err != nil {
		return nil, err
	}
	outputs := map[btcutil.Address]btcutil.Amount{
		outAddr: btcutil.Amount((utxo.Amount - 0.1) * 1e8),
	}
	//	创建交易
	rawTx, err := Client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		return nil, err
	}

	ret := CovertMsgTx{
		msgtx:   rawTx,
		isSOver: nil,
	}
	return &ret, nil
}

// 签名交易，嵌入秘密消息，并保存特殊q
func SignTrans(rawTx *CovertMsgTx, embedMsg *string) (*CovertMsgTx, error) {
	signedTx, complete, err, isSOvers := Client.SignRawTransaction(rawTx.msgtx, embedMsg)
	if err != nil {
		return nil, err
	}
	if !complete {
		return nil, errors.New("transaction signing incomplete")
	}
	ret := CovertMsgTx{
		msgtx:   signedTx,
		isSOver: isSOvers,
	}
	// 保存签名
	//if embedMsg != nil {
	//	sig := hex.EncodeToString(signedTx.TxIn[0].SignatureScript)
	//	sign, ok := DataAnalysis.GetSignatureFromHex(sig)
	//	if !ok {
	//		return nil, errors.New("Data Analysis Error")
	//	}
	//	err = DataAnalysis.AppendSignature(sign, "DataAnalysis/DataSet/CovertSig_1.xlsx")
	//	if err != nil {
	//		return nil, err
	//	}
	//} else {
	//	sig := hex.EncodeToString(signedTx.TxIn[0].SignatureScript)
	//	sign, ok := DataAnalysis.GetSignatureFromHex(sig)
	//	if !ok {
	//		return nil, errors.New("Data Analysis Error")
	//	}
	//	err = DataAnalysis.AppendSignature(sign, "DataAnalysis/DataSet/NormalSig_1.xlsx")
	//	if err != nil {
	//		return nil, err
	//	}
	//}
	return &ret, nil
}

// 广播交易
func BroadTrans(signedTx *CovertMsgTx) (*chainhash.Hash, error) {
	txHash, err := Client.SendRawTransaction(signedTx.msgtx, false)
	if err != nil {
		return nil, err
	}
	Share.IsTxSignOver[*txHash] = signedTx.isSOver[0]
	return txHash, nil
}

func ImportPrivkey(key *KeyDerivation.PrivateKey) error {
	prikWIF, err := KeyDerivation.ToWIF(key.Key)
	if err != nil {
		return err
	}
	wif, _ := btcutil.DecodeWIF(prikWIF)
	err = Client.ImportPrivKey(wif)
	if err != nil {
		return err
	}
	return nil
}

// 将字符串每32字节划分
func SplitStrBy32bytes(covertMsg string) []string {
	byteSlice := []byte(covertMsg)
	chunkSize := 32
	var chunks []string

	for i := 0; i < len(byteSlice); i += chunkSize {
		end := i + chunkSize
		if end > len(byteSlice) {
			end = len(byteSlice)
		}
		chunks = append(chunks, string(byteSlice[i:end]))
	}
	return chunks
}

// AddCntPrivKeys 为第i组主密钥追加派生cnt个密钥
func AddCntPrivKeys(id, cnt int) error {
	msk := MskSet[id]
	numPrik := len(PrikSet[id])
	for i := 0; i < cnt; i++ {
		key, err := msk.ChildPrivateKeyDeprive(uint32(numPrik + i))
		if err != nil {
			return err
		}
		err = ImportPrivkey(key)
		if err != nil {
			return err
		}
		PrikSet[id] = append(PrikSet[id], key)
		address, err := KeyDerivation.GetAddressByPrivKey(key)
		if err != nil {
			return err
		}
		AddressSet[id] = append(AddressSet[id], address)
	}
	return nil
}

// GenerateCntBankKeys 生成cnt个银行地址
func GenerateCntBankKeys(cnt int) error {
	for i := 0; i < cnt; i++ {
		key, err := BankRoot.ChildPrivateKeyDeprive(uint32(BankId))
		if err != nil {
			return err
		}
		err = ImportPrivkey(key)
		if err != nil {
			return err
		}
		BankPrikSet = append(BankPrikSet, key)
		BankId++
	}
	return nil
}
