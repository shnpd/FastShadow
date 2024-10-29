package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil"
)

func main() {
	// 已知的私钥字节
	privateKeyHex := "d4b88dfb7e63debfd1c46c08f3d19a9f2b5d872511417f7d944a5221f5e6a6ad"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		fmt.Println("Error decoding hex:", err)
		return
	}

	// 生成私钥对象
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKeyBytes)

	// 计算公钥
	pubKey := privKey.PubKey()

	// 生成地址
	addr, err := btcutil.NewAddressPubKey(pubKey.SerializeCompressed(), &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println("Error creating address:", err)
		return
	}

	// 输出地址
	fmt.Println("Bitcoin Address:", addr.EncodeAddress())
}
