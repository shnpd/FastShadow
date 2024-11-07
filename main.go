package main

import (
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
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

	// Source and destination addresses
	sourceAddress := "SMyjjZCS3Wgn3xidhGs92AFNPxQ1AhuvXk"
	destinationAddress := "SStEkSyJbAHXdcrfb4GQiLmkS7pEGLDW2Q"

	if err != nil {
		log.Fatalf("Error decoding source address: %v", err)
	}

	if err != nil {
		log.Fatalf("Error decoding destination address: %v", err)
	}

	// 获取源地址的utxo
	utxos, err := client.ListUnspentMinMax(1, 9999999)
	if err != nil {
		log.Fatalf("Error fetching unspent outputs: %v", err)
	}
	var utxosByAddr []btcjson.ListUnspentResult
	for _, utxo := range utxos {
		if utxo.Address == sourceAddress {
			utxosByAddr = append(utxosByAddr, utxo)
		}
	}
	//构造输入
	var inputs []btcjson.TransactionInput
	var totalInput btcutil.Amount
	for _, utxo := range utxosByAddr {
		inputs = append(inputs, btcjson.TransactionInput{
			Txid: utxo.TxID,
			Vout: utxo.Vout,
		})
		totalInput += btcutil.Amount(utxos[0].Amount)
	}

	//构造输出（输入全部用作输出，没有交易费）
	destAddr, _ := btcutil.DecodeAddress(destinationAddress, &chaincfg.SimNetParams)
	outputs := map[btcutil.Address]btcutil.Amount{
		destAddr: totalInput,
	}

	// 创建交易
	rawTx, err := client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		log.Fatalf("Error creating raw transaction: %v", err)
	}

	//	签名交易
	t := "1234"
	signedTx, complete, err := client.SignRawTransaction(rawTx, &t)
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}
	if !complete {
		log.Fatalf("Transaction signing incomplete")
	}
	//	广播交易
	txHash, err := client.SendRawTransaction(signedTx, false)
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}

	log.Printf("Transaction sent successfully: %v", txHash)
}
