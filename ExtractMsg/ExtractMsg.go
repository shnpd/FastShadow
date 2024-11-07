// 输入交易id，输出隐蔽消息
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"log"
	"strconv"
)

func main() {

	// 设置RPC客户端连接的配置
	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:28335", // 替换为你的btcwallet的RPC地址
		User:         "simnet",          // 在btcwallet配置文件中定义的RPC用户名
		Pass:         "simnet",          // 在btcwallet配置文件中定义的RPC密码
		HTTPPostMode: true,              // 使用HTTP POST模式
		DisableTLS:   true,              // 禁用TLS
		Params:       "simnet",          // 连接到simnet网
	}

	// 创建新的RPC客户端
	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatalf("Error creating new client: %v", err)
	}
	defer client.Shutdown()

	//获取交易
	txhash := "935cbf095c7927e0348d391fce2f6f7be13be7c8769b88c34d882e897cec3362"
	txHash, err := chainhash.NewHashFromStr(txhash)
	if err != nil {
		fmt.Println(err)
	}
	rawTx, err := client.GetRawTransaction(txHash)
	if err != nil {
		fmt.Println(nil)
	}

	//获取私钥
	addressStr := "SMyjjZCS3Wgn3xidhGs92AFNPxQ1AhuvXk"
	address, err := btcutil.DecodeAddress(addressStr, &chaincfg.SimNetParams)
	privateKeyWif, err := client.DumpPrivKey(address)
	fmt.Println(privateKeyWif)
	//提取签名
	signatureScript := hex.EncodeToString(rawTx.MsgTx().TxIn[0].SignatureScript)
	sig := getsigFromHex(signatureScript)
	r := sig.R()
	s := sig.S()
	s.Negate()
	//计算哈希
	var script []byte
	var hashType txscript.SigHashType
	tx := new(wire.MsgTx)
	var idx int
	idx = 0
	tx = rawTx.MsgTx()
	hashType = 1
	script = getScript(rawTx.MsgTx(), client)
	hash, _ := txscript.CalcSignatureHash(script, hashType, tx, idx)

	//	提取k
	k := recoverK(&privateKeyWif.PrivKey.Key, &r, &s, hash)
	t := k.Bytes()
	fmt.Println(string(t[:]))
	// 提取d
	d := recoverD(k, &r, &s, hash)
	fmt.Println("恢复密钥：", d.String())
	fmt.Println("实际密钥：", privateKeyWif.PrivKey.Key.String())
}

// 从Hex字段提取签名
func getsigFromHex(HexSig string) *ecdsa.Signature {
	lenSigByte := HexSig[4:6]
	t, _ := strconv.ParseInt(lenSigByte, 16, 0)
	sigStr := HexSig[2 : 6+2*t]
	//解码
	asmByte, _ := hex.DecodeString(sigStr)
	sig, _ := ecdsa.ParseDERSignature(asmByte)
	return sig
}

// 获取生成utxo的交易的输出脚本
func getScript(tx *wire.MsgTx, client *rpcclient.Client) []byte {
	txhash := tx.TxIn[0].PreviousOutPoint.Hash
	txraw, _ := client.GetRawTransaction(&txhash)
	script := txraw.MsgTx().TxOut[0].PkScript
	return script
}

// 已知私钥求随机数
func recoverK(d, r, s *secp256k1.ModNScalar, hash []byte) *secp256k1.ModNScalar {
	var k *secp256k1.ModNScalar
	var e secp256k1.ModNScalar
	e.SetByteSlice(hash)
	sinv := new(secp256k1.ModNScalar).InverseValNonConst(s)
	k = new(secp256k1.ModNScalar).Mul2(d, r).Add(&e).Mul(sinv)
	return k
}

// 已知随机数求私钥
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
