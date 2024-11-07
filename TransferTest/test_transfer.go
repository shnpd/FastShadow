package main

import (
	"covertCommunication/KeyDerivation"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"log"
)

const btc = 100000000

var client *rpcclient.Client

// 初始化钱包
func initWallet() {
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
	client, _ = rpcclient.New(connCfg, nil)
	client.WalletPassphrase("ts0", 6000)
}

func main() {
	initWallet()

	transfer(0, 5)
	rawTx := generateTransFromUTXO("bc508fd9a4412eac3270291d2ac2b4a6922028ed101d729711df71f743a9ded0", "SRMMzEu1AtnTfQorrE1CAiTQ2AdVgfiwp6", 10)
	signTx := signTrans2(rawTx, nil)
	txid := broadTrans2(signTx)
	fmt.Println(txid)
}

// 向第id个私钥下派生的cnt个地址各转入一个utxo
func transfer(id, cnt int) error {
	skroot, _ := KeyDerivation.GenerateMasterKey([]byte("initseed"))
	skid, _ := skroot.ChildPrivateKeyDeprive(uint32(id))
	importPrivkey(skid)

	utxos, _ := client.ListUnspent()
	num := 0
	for _, utxo := range utxos {
		if num == cnt {
			break
		}
		if utxo.Address != "SMyjjZCS3Wgn3xidhGs92AFNPxQ1AhuvXk" {
			continue
		}
		skidnum, _ := skid.ChildPrivateKeyDeprive(uint32(num))
		err := importPrivkey(skidnum)

		destAddr, err := KeyDerivation.GetAddressByPrivKey(skidnum)
		if err != nil {
			return err
		}
		sourceTxid := utxo.TxID
		rawTx := generateTransFromUTXO(sourceTxid, destAddr, 10)
		signTx := signTrans2(rawTx, nil)
		txid := broadTrans2(signTx)
		fmt.Printf("transfer to address:%s txid:%s \n", destAddr, txid)
		num++
	}
	return nil
}
func importPrivkey(key *KeyDerivation.PrivateKey) error {
	prikWIF, err := KeyDerivation.ToWIF(key.Key)
	if err != nil {
		return err
	}
	wif, _ := btcutil.DecodeWIF(prikWIF)
	err = client.ImportPrivKey(wif)
	if err != nil {
		return err
	}
	return nil
}

// 生成sourceAddr到destAddr的原始交易（将UTXO全部转给目标地址，没有交易费）
func generateTransFromUTXO(txid, destAddr string, amount int) *wire.MsgTx {
	// 构造输入
	var inputs []btcjson.TransactionInput
	inputs = append(inputs, btcjson.TransactionInput{
		Txid: txid,
		Vout: 0,
	})
	//	构造输出
	outAddr, _ := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	outputs := map[btcutil.Address]btcutil.Amount{
		outAddr: btcutil.Amount((amount - 1) * btc),
	}
	//	创建交易
	rawTx, err := client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		log.Fatalf("Error creating raw transaction: %v", err)
	}
	return rawTx
}

// 签名交易，嵌入秘密消息
func signTrans2(rawTx *wire.MsgTx, embedMsg *string) *wire.MsgTx {
	signedTx, complete, err, isSOvers := client.SignRawTransaction(rawTx, embedMsg)
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}
	if !complete {
		log.Fatalf("Transaction signing incomplete")
	}
	fmt.Println(isSOvers)
	return signedTx
}

// 广播交易
func broadTrans2(signedTx *wire.MsgTx) string {
	txHash, err := client.SendRawTransaction(signedTx, false)
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}
	return txHash.String()
}
