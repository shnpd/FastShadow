package main

import (
	"covertCommunication/KeyDerivation"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
)

const (
	//待嵌入消息
	Covertmsg = "Hello! This is Shihaonan, and i will send a message based blockchain, best wishes!"
)

var (
	pkroot   *KeyDerivation.PublicKey      //根公钥
	skroot   *KeyDerivation.PrivateKey     //根私钥
	initSeed []byte                        //初始种子
	prikSet  [][]*KeyDerivation.PrivateKey //私钥集合,每次消息传递需要一个私钥数组
	pubkSet  [][]*KeyDerivation.PublicKey  //公钥集合
	address  [][]string                    //地址集合
	client   *rpcclient.Client             //客户端
	num      int                           //通信序号
)

// init 生成根密钥对
func init() {
	//根据初始化种子生成根密钥对
	initSeed = []byte("initseed")
	skroot, _ = KeyDerivation.GenerateMasterKey(initSeed)
	pkroot = KeyDerivation.EntirePublicKeyForPrivateKey(skroot)
}

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

// 预先生成第1组私钥,后续第num次通信生成第num+1组私钥,生成num->num+1的交易

func main() {
	initWallet()
	defer client.Shutdown()

	//基于skroot派生两个私钥，一个用来发送，一个用来接收
	sk1, _ := skroot.ChildPrivateKeyDeprive(1)
	sk2, _ := skroot.ChildPrivateKeyDeprive(2)
	//	将私钥转化为密钥种子
	seed1 := sk1.SerializePriv()
	seed2 := sk2.SerializePriv()
	//	计算嵌入消息的字节数，每个交易可以嵌入32字节
	byteCnt := len([]byte(Covertmsg))
	msgCnt := (byteCnt + 31) / 32
	// 字符串每32字节划分
	splitMsg := splitStr()
	//	生成addrCnt个私钥以备嵌入
	generatePrivKey(msgCnt, seed1)
	generatePrivKey(msgCnt, seed2)
	//	将私钥导入钱包以便发送交易
	for i := 0; i < msgCnt; i++ {
		prikWIF := KeyDerivation.ToWIF(prikSet[0][i].Key, "simnet")
		wif, _ := btcutil.DecodeWIF(prikWIF)
		err := client.ImportPrivKey(wif)
		if err != nil {
			log.Fatalf("ImportPrivKey error: %s", err)
		}
	}

	// 保存私钥对应的地址以便筛选交易
	saveAddress(0, msgCnt)
	saveAddress(1, msgCnt)

	//	发送交易
	var covertTxid []string
	covertTxid = sendCovertTransaction(msgCnt, splitMsg)
	for _, v := range covertTxid {
		fmt.Printf("Covert transaction id:", v)
	}
}

// 派生嵌入私钥
func generatePrivKey(cnt int, seed []byte) {
	var privSetTemp []*KeyDerivation.PrivateKey
	masterKey1, _ := KeyDerivation.GenerateMasterKey(seed)
	for i := 0; i < cnt; i++ {
		key, _ := masterKey1.ChildPrivateKeyDeprive(uint32(i))
		privSetTemp = append(privSetTemp, key)
	}
	prikSet = append(prikSet, privSetTemp)
}

// 保存第num组私钥对应的地址
func saveAddress(num, cnt int) {
	var addressTemp []string
	for i := 0; i < cnt; i++ {
		prikWIF := KeyDerivation.ToWIF(prikSet[num][i].Key, "simnet")
		addressByWIF, _ := KeyDerivation.GetAddressByWIF(prikWIF)
		addressTemp = append(addressTemp, addressByWIF)
	}
	address = append(address, addressTemp)
}

// 将字符串每32字节划分
func splitStr() []string {
	byteSlice := []byte(Covertmsg)
	chunkSize := 32
	var chunks []string

	for i := 0; i < len(byteSlice); i += chunkSize {
		end := i + chunkSize
		if end > len(byteSlice) {
			end = len(byteSlice)
		}
		chunks = append(chunks, string(byteSlice[i:end]))
	}
	return chunks
}

// 发送隐蔽交易
func sendCovertTransaction(msgCnt int, splitMsg []string) (covertTxid []string) {
	//	计算地址到UTXO的映射
	allUTXO, _ := client.ListUnspent()
	UTXObyAddress := make(map[string][]btcjson.ListUnspentResult)
	for _, utxo := range allUTXO {
		UTXObyAddress[utxo.Address] = append(UTXObyAddress[utxo.Address], utxo)
	}
	//	构造addrcnt个隐蔽交易,每个交易只有1个输入1个输出
	for i := 0; i < msgCnt; i++ {
		// 构造输入
		var inputs []btcjson.TransactionInput
		if len(UTXObyAddress[address[0][i]]) == 0 {
			log.Fatalf("%s have not UTXO", address[0][i])
		}
		utxo := UTXObyAddress[address[0][i]][0]
		inputs = append(inputs, btcjson.TransactionInput{
			Txid: utxo.TxID,
			Vout: utxo.Vout,
		})
		//	构造输出
		destinationAddress := address[1][i]
		destAddr, _ := btcutil.DecodeAddress(destinationAddress, &chaincfg.SimNetParams)
		outputs := map[btcutil.Address]btcutil.Amount{
			destAddr: btcutil.Amount(1),
		}
		//	创建交易
		rawTx, err := client.CreateRawTransaction(inputs, outputs, nil)
		if err != nil {
			log.Fatalf("Error creating raw transaction: %v", err)
		}
		//	签名交易(嵌入消息)
		coverMsg := splitMsg[i]
		signedTx, complete, err := client.SignRawTransaction(rawTx, &coverMsg)
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
		covertTxid = append(covertTxid, txHash.String())
	}
	return covertTxid
}
