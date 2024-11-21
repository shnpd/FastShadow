package RPC

import (
	"github.com/btcsuite/btcd/rpcclient"
)

// InitClient 初始化客户端，传入网络类型，其中user和pass我们在启动服务时都设置为对应的网络类型字符串，为简化过程不启动TLS
func InitClient(host, netType string) *rpcclient.Client {
	// 设置RPC客户端连接的配置
	connCfg := &rpcclient.ConnConfig{
		Host:         host,    // 替换为你的btcwallet的RPC地址
		User:         netType, // 在btcwallet配置文件中定义的RPC用户名
		Pass:         netType, // 在btcwallet配置文件中定义的RPC密码
		HTTPPostMode: true,    // 使用HTTP POST模式
		DisableTLS:   true,    // 禁用TLS
		Params:       netType, // 连接到simnet网
	}

	// 创建新的RPC客户端
	client, _ := rpcclient.New(connCfg, nil)
	// 默认解锁钱包
	//err := client.WalletPassphrase("ts0", 6000)
	//if err != nil {
	//	fmt.Println(err)
	//}
	return client
}
