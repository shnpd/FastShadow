package main

import (
	"covertCommunication/KeyDerivation"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func main() {
	seed, err := KeyDerivation.NewSeed()
	seed = []byte("111")
	if err != nil {
		return
	}
	masterKey, err := KeyDerivation.GenerateMasterKey(seed)
	if err != nil {
		return
	}
	//key := masterKey.Key

	key12, _ := masterKey.ChildPrivateKeyDeprive(2)
	key13, _ := masterKey.ChildPrivateKeyDeprive(3)
	key14, _ := masterKey.ChildPrivateKeyDeprive(4)
	fmt.Println(KeyDerivation.ToWIF(key12.Key, "simnet"))
	fmt.Println(KeyDerivation.ToWIF(key13.Key, "simnet"))
	fmt.Println(KeyDerivation.ToWIF(key14.Key, "simnet"))

	key12Addr, _ := getAddressByWIF("4MWc2dmFrDhZfjsKZydjkjYym9BycC1y3aHvDCrjjsUuQTfxndZ")
	fmt.Println(key12Addr)
}

func getAddressByWIF(keywif string) (string, error) {
	// 解析WIF格式
	privKey, err := btcutil.DecodeWIF(keywif)
	if err != nil {
		fmt.Println("Error decoding WIF:", err)
		return "", err
	}
	// 计算公钥
	pubKey := privKey.PrivKey.PubKey()
	// 生成地址
	addr, err := btcutil.NewAddressPubKey(pubKey.SerializeUncompressed(), &chaincfg.SimNetParams)
	if err != nil {
		fmt.Println("Error creating address:", err)
		return "", err
	}
	// 输出地址
	return addr.EncodeAddress(), nil
}
