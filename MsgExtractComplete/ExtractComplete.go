package main

import (
	"covertCommunication/KeyDerivation"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
)

var (
	pkroot     *KeyDerivation.PublicKey //根公钥
	kleak      string                   //泄露随机数
	commId     = 0                      //通信序号
	layer1Pubk []*KeyDerivation.PublicKey
	client     *rpcclient.Client //客户端
)

// 已知根公钥以及泄露随机数
func init() {

}
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

}

// 筛选泄露交易，第commId次通信使用第commId个一层私钥
func filterCoverTx(commId int) *wire.MsgTx {
	pubkey, _ := pkroot.ChildPublicKeyDeprive(uint32(commId))
	addr := KeyDerivation.GetAddressByPubKey(pubkey)
	client.ListTransactions()
}
