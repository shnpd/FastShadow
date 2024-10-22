package test

import (
	"encoding/hex"
	"log"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func main() {
	// 交易信息
	txid := "03ef7f3fe66b77248a3217b7a73a5641dcb47e9208edad1218d1cd833a70e22d"
	signatureHex := "3045022100d382707843a407bbfb2cf1cac4c378fae4835f3edaa77e2fc927ca7560a36eb6022051a08c8484a91290e3c90f6a4d42703fa52b0a4873bcb5a5f7c3db9331a28e8801"
	pubKeyHex := "0239d66ca7a8ed7a8efe1a418749e2f8b770d7227a311f940f98e6eb98e7d7c2dc"

	// 解析签名和公钥
	signatureBytes, _ := hex.DecodeString(signatureHex)
	pubKeyBytes, _ := hex.DecodeString(pubKeyHex)

	// 创建一个交易（示例，真实交易应根据具体情况构建）
	tx := wire.NewMsgTx(1) // 版本号

	// 验证签名
	valid := txscript.VerifySignature(tx, tx.TxIn[0].SignatureScript, &chaincfg.SimNetParams, txscript.SigHashAll, 0, signatureBytes, pubKeyBytes)
	if valid {
		log.Println("签名有效")
	} else {
		log.Println("签名无效")
	}
}
