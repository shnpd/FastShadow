package main

import (
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"strconv"
)

// getsigFromHex 从Hex字段提取签名
func getsigFromHex(HexSig string) *ecdsa.Signature {
	lenSigByte := HexSig[4:6]
	t, _ := strconv.ParseInt(lenSigByte, 16, 0)
	sigStr := HexSig[2 : 6+2*t]
	//解码
	asmByte, _ := hex.DecodeString(sigStr)
	sig, _ := ecdsa.ParseDERSignature(asmByte)
	return sig
}

// getScript 获取生成utxo的交易的输出脚本
func getScript(tx *wire.MsgTx, client *rpcclient.Client) []byte {
	txhash := tx.TxIn[0].PreviousOutPoint.Hash
	txraw, _ := client.GetRawTransaction(&txhash)
	script := txraw.MsgTx().TxOut[0].PkScript
	return script
}

// recoverK 已知私钥求随机数
func recoverK(d, r, s *secp256k1.ModNScalar, hash []byte) *secp256k1.ModNScalar {
	var k *secp256k1.ModNScalar
	var e secp256k1.ModNScalar
	e.SetByteSlice(hash)
	dr := new(secp256k1.ModNScalar).Mul2(d, r)
	sum := e.Add(dr)
	sinv := new(secp256k1.ModNScalar).InverseValNonConst(s)
	k = sinv.Mul(sum)
	return k
}

// recoverD 已知随机数求私钥
func recoverD(k, r, s *secp256k1.ModNScalar, hash []byte) *secp256k1.ModNScalar {
	var d *secp256k1.ModNScalar
	var e secp256k1.ModNScalar
	e.SetByteSlice(hash)

	ks := new(secp256k1.ModNScalar).Mul2(k, s)
	ksMinusE := ks.Add(e.Negate())

	sinr := new(secp256k1.ModNScalar).InverseValNonConst(r)
	d = sinr.Mul(ksMinusE)
	return d
}

// getInputUTXO 获取交易的输入UTXO
func getInputUTXO(txid *chainhash.Hash) ([]wire.OutPoint, error) {
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
