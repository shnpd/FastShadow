package main

import (
	"covertCommunication/Crypto"
	"covertCommunication/Key"
	"covertCommunication/RPC"
	"covertCommunication/Transaction"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
)

var (
	skroot *Key.PrivateKey
	pkroot *Key.PublicKey //根公钥

	netType string
	bankmsk *Key.PrivateKey
	// 已生成的银行地址个数，设置为全局变量保存
	bankNum       int
	bankAddresses []string
	// AES加密密钥
	keyAES []byte
)

// init 生成根密钥对
func init() {
	initSeed := []byte("initseed")
	skroot, _ = Key.GenerateMasterKey(initSeed)
	pkroot = Key.EntirePublicKeyForPrivateKey(skroot)
	bankmsk, _ = skroot.ChildPrivateKeyDeprive(9999)
	netType = "simnet"
	bankNum = 0
	keyAES = []byte("1234567890123456")

}

func main() {

	client := RPC.InitClient("localhost:28335", netType)
	// 解锁钱包
	err := client.WalletPassphrase("ts0", 6000)
	if err != nil {
		return
	}
	defer client.Shutdown()

	kLeak := []byte("leak Random")
	endFlag := "ENDEND" //结束标志
	covertMsg := "123456789012345678901234567890123456789012345678901234567890"

	// 添加结束标志并加密，加密后的消息可以近似认为是随机的，这样作为随机因子嵌入时与实际生成的随机因子无法区分
	covertMsg += endFlag

	// 计算嵌入消息的字节数以及需要的隐蔽交易数（每个交易可以嵌入32字节）
	byteCnt := len(covertMsg)
	msgCnt := (byteCnt + 31) / 32
	// 字符串每32字节划分
	splitMsg := Split32bytes([]byte(covertMsg))

	// 加密每个分组
	var encryptMsg [][]byte
	for _, v := range splitMsg {
		cipher, err := Crypto.Encrypt(v, keyAES)
		if err != nil {
			log.Fatal(err)
		}
		encryptMsg = append(encryptMsg, cipher)
	}
	//通信轮数
	round := 1
	// 生成当前轮的主密钥,并派生多个私钥
	msk1, err := Key.GenerateMsk(client, skroot, round-1, netType)
	if err != nil {
		log.Fatal(err)
	}
	skList1, err := msk1.DeprivCntKeys(client, 0, 10, netType)
	if err != nil {
		log.Fatal(err)
	}
	var addressList1 []string
	for _, v := range skList1 {
		addr, err := Key.GetAddressByPrivateKey(v, netType)
		if err != nil {
			log.Fatal(err)
		}
		addressList1 = append(addressList1, addr)
	}
	//生成下一个主密钥并派生msgCnt个密钥用来接收交易
	msk2, err := Key.GenerateMsk(client, skroot, round, netType)
	if err != nil {
		log.Fatal(err)
	}
	skList2, err := msk2.DeprivCntKeys(client, 0, msgCnt, netType)
	if err != nil {
		log.Fatal(err)
	}
	var addressList2 []string
	for _, v := range skList2 {
		addr, err := Key.GetAddressByPrivateKey(v, netType)
		if err != nil {
			log.Fatal(err)
		}
		addressList2 = append(addressList2, addr)
	}

	//使用银行地址集平衡发送地址集的UTXO数量
	//err = TransferBank(client, msk1, addressList1, msgCnt, bankmsk)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//	发送隐蔽交易
	var covertTxid []*chainhash.Hash
	covertTxid, err = SendCovertTransaction(client, addressList1, addressList2, msgCnt, encryptMsg)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, v := range covertTxid {
		fmt.Printf("Covert transaction id: %s\n", v.String())
	}

	// 发送泄露交易
	leakTrans, err := SendLeakTrans(client, msk1, &kLeak)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("leak transaction id: %s\n", leakTrans.String())
	_, err = client.Generate(1)
	if err != nil {
		log.Fatal(err)
	}
}

// Split32bytes 将字符串每32字节划分
func Split32bytes(msg []byte) [][]byte {
	chunkSize := 32
	var chunks [][]byte

	for i := 0; i < len(msg); i += chunkSize {
		end := i + chunkSize
		if end > len(msg) {
			end = len(msg)
		}
		chunks = append(chunks, msg[i:end])
	}
	return chunks
}

// SendLeakTrans TODO:生成银行地址作为接收地址
// SendLeakTrans 发送round轮的主密钥的泄露交易，返回泄露交易id
func SendLeakTrans(client *rpcclient.Client, msk *Key.PrivateKey, kLeak *[]byte) (*chainhash.Hash, error) {
	sourceAddr, err := Key.GetAddressByPrivateKey(msk, netType)
	if err != nil {
		return nil, err
	}
	txId, err := Transaction.EntireSendTrans(client, sourceAddr, "SYZPAZEjXy7S4jbsUHqWUgv2FYomsR3RVS", 1, kLeak)
	if err != nil {
		return nil, err
	}
	return txId, nil
}

// TransferBank 传入发送地址集合，每个地址拥有一个utxo，一共需要msgCnt个utxo，多退少补
func TransferBank(client *rpcclient.Client, msk *Key.PrivateKey, addresses []string, msgCnt int, bankMsk *Key.PrivateKey) error {
	utxoNum := len(addresses)
	//utxo有多余，生成银行地址，将多余的utxo转入
	if utxoNum > msgCnt {
		minus := utxoNum - msgCnt
		bankPrik, err := bankMsk.DeprivCntKeys(client, bankNum, minus, netType)
		if err != nil {
			return err
		}
		for _, v := range bankPrik {
			addr, err := Key.GetAddressByPrivateKey(v, netType)
			if err != nil {
				return err
			}
			bankAddresses = append(bankAddresses, addr)
		}
		bankNum += minus

		for i := 0; i < minus; i++ {
			// 创建转出交易
			sourceAddr := addresses[msgCnt+i]
			destAddr := bankAddresses[i]
			_, err := Transaction.EntireSendTrans(client, sourceAddr, destAddr, 0, nil)
			if err != nil {
				return err
			}
		}
	} else {
		//	utxo数量不足，生成通信地址，从银行地址集提取
		minus := msgCnt - utxoNum
		for i := 0; i < minus; i++ {
			// 提取银行地址(默认银行地址足够用)
			sourceAddr := bankAddresses[0]
			bankAddresses = bankAddresses[1:]
			// 为主密钥msk追加地址接收银行utxo
			keys, err := msk.DeprivCntKeys(client, utxoNum, 1, netType)
			if err != nil {
				return err
			}
			destAddr, err := Key.GetAddressByPrivateKey(keys[0], netType)
			if err != nil {
				return err
			}
			_, err = Transaction.EntireSendTrans(client, sourceAddr, destAddr, 0, nil)
			if err != nil {
				return err
			}
			utxoNum++
			addresses = append(addresses, destAddr)
		}
	}
	return nil
}

// SendCovertTransaction 发送隐蔽交易
func SendCovertTransaction(client *rpcclient.Client, sourceAddresses, destAddresses []string, msgCnt int, msgList [][]byte) ([]*chainhash.Hash, error) {
	var covertTxid []*chainhash.Hash
	for i := 0; i < msgCnt; i++ {
		msg := msgList[i]
		txId, err := Transaction.EntireSendTrans(client, sourceAddresses[i], destAddresses[i], 1, &msg)
		if err != nil {
			return nil, err
		}
		covertTxid = append(covertTxid, txId)
	}
	return covertTxid, nil
}
