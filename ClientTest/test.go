package main

import (
	"fmt"
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
	//addr, _ := btcutil.DecodeAddress("SiGGuKwQ2WP1uZ63TBVk1E6mb3qPyqrnEg", &chaincfg.SimNetParams)
	//utxo, _ := client.ListUnspent()
	transactions, err := client.ListTransactions("default")
	//fmt.Println(utxo)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(transactions)
}
