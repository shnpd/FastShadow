package main

import (
	"covertCommunication/KeyDerivation"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/rpcclient"
)

var (
	Pkroot        *KeyDerivation.PublicKey                       //根公钥
	Skroot        *KeyDerivation.PrivateKey                      //根私钥
	InitSeed      []byte                                         //初始种子
	PrikSet       = make([][]*KeyDerivation.PrivateKey, 30)      //私钥集合,每次消息传递需要一个私钥数组
	PubkSet       = make([][]*KeyDerivation.PublicKey, 30)       //公钥集合
	AddressSet    = make([][]string, 30)                         //地址集
	MskSet        = make([]*KeyDerivation.PrivateKey, 30)        //主密钥集合
	Client        *rpcclient.Client                              //客户端
	Kleak         string                                         //泄露消息
	BankPrikSet   []*KeyDerivation.PrivateKey                    //银行密钥集合
	BankRoot      *KeyDerivation.PrivateKey                      //银行根密钥
	BankId        = 0                                            //下一个银行地址序号
	UTXObyAddress = make(map[string][]btcjson.ListUnspentResult) //地址持有的UTXO的映射
	NetType       = "simnet"                                     //网络类型
	EndFlag       = "ENDEND"                                     //结束标志
	MiningAddr    = "SYZPAZEjXy7S4jbsUHqWUgv2FYomsR3RVS"
	btc           = 100000000
	Covertmsg     = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
)
