package main

import (
	"covertCommunication/KeyDerivation"
	"covertCommunication/Share"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
)

// init 生成根密钥对
func init() {
	initSeed = []byte("initseed")
	skroot, _ = KeyDerivation.GenerateMasterKey(initSeed)
	pkroot = KeyDerivation.EntirePublicKeyForPrivateKey(skroot)
	bankRoot, _ = KeyDerivation.GenerateMasterKey([]byte("bank"))
	kleak = "leak Random"
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
	err := client.WalletPassphrase("ts0", 6000)
	if err != nil {
		fmt.Println(err)
	}

}

func main() {
	initWallet()
	defer client.Shutdown()

	//	预先生成第一组私钥
	err := generateNewCntPrivKeys(5)
	if err != nil {
		fmt.Println(err)
		return
	}
	//通信轮数=主密钥数（初始有一个主密钥，即为第一轮通信）
	round := len(mskSet)

	//	计算嵌入消息的字节数以及需要的隐蔽交易数（每个交易可以嵌入32字节）
	Covertmsg := "Hello! This is Shihaonan, and i will send a message based blockchain, best wishes!"
	// 添加结束标志
	Covertmsg += "end"
	byteCnt := len([]byte(Covertmsg))
	msgCnt := (byteCnt + 31) / 32
	// 字符串每32字节划分
	splitMsg := splitStrBy32bytes(Covertmsg)

	//	生成msgCnt个私钥用来接收交易
	err = generateNewCntPrivKeys(msgCnt)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = updateMapUTXOFromAddr()
	if err != nil {
		fmt.Println(err)
		return
	}

	// 使用银行地址集平衡发送地址集的UTXO数量
	err = transferBank(round, msgCnt)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = updateMapUTXOFromAddr()
	if err != nil {
		fmt.Println(err)
		return
	}

	//	发送隐蔽交易
	var covertTxid []*chainhash.Hash
	covertTxid, err = sendCovertTransaction(round, msgCnt, splitMsg)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, v := range covertTxid {
		fmt.Printf("Covert transaction id: %s\n", v.String())
	}

	// 发送泄露交易
	leakTrans, err := sendLeakTrans(round)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("leak transaction id: %s\n", leakTrans.String())
	fmt.Println(Share.IsTxSignOver)
}

// TODO:生成银行地址作为接收地址
// sendLeakTrans 发送round轮的主密钥的泄露交易，返回泄露交易id
func sendLeakTrans(round int) (*chainhash.Hash, error) {
	mskId := round - 1
	sourceAddr, err := KeyDerivation.GetAddressByPrivKey(mskSet[mskId])
	if err != nil {
		return nil, err
	}
	rawTx, err := generateTrans(sourceAddr, "SYZPAZEjXy7S4jbsUHqWUgv2FYomsR3RVS")
	if err != nil {
		return nil, err
	}
	signedTx, err := signTrans(rawTx, &kleak)
	if err != nil {
		return nil, err
	}
	txid, err := broadTrans(signedTx)
	if err != nil {
		return nil, err
	}
	return txid, nil
}

// transferBank 第round轮通信需要msgCnt个UTXO，处理发送地址持有的UTXO，多退少补，第round轮通信的主密钥序号为round-1（从0开始计算）
func transferBank(round, msgCnt int) error {
	mskId := round - 1
	utxoNum := len(prikSet[mskId])

	//utxo有多余，生成银行地址，将多余的utxo转入
	if utxoNum > msgCnt {
		minus := utxoNum - msgCnt
		err := generateCntBankKeys(minus)
		if err != nil {
			return err
		}
		for i := 0; i < minus; i++ {
			// 创建转出交易
			sourceAddr := addressSet[mskId][msgCnt+i]
			if len(UTXObyAddress[sourceAddr]) == 0 {
				continue
			}
			destAddr, err := KeyDerivation.GetAddressByPrivKey(bankPrikSet[len(bankPrikSet)-i-1])
			if err != nil {
				return err
			}
			rawTx, err := generateTrans(sourceAddr, destAddr)
			if err != nil {
				return err
			}
			// 签名交易，该交易不嵌入信息
			signedTx, err := signTrans(rawTx, nil)
			if err != nil {
				return err
			}
			_, err = broadTrans(signedTx)
			if err != nil {
				return err
			}
		}
	} else {
		//	utxo数量不足，生成通信地址，从银行地址集提取
		minus := msgCnt - utxoNum
		for i := 0; i < minus; i++ {
			// 提取银行地址(默认银行地址足够用)
			bankPrik := bankPrikSet[0]
			bankPrikSet = bankPrikSet[1:]
			sourceAddr, err := KeyDerivation.GetAddressByPrivKey(bankPrik)
			if err != nil {
				return err
			}
			// 为主密钥mskid追加地址接收银行utxo
			err = addCntPrivKeys(mskId, 1)
			if err != nil {
				return err
			}
			destAddr := addressSet[mskId][utxoNum+i]
			rawTx, err := generateTrans(sourceAddr, destAddr)
			if err != nil {
				return err
			}
			signedTx, err := signTrans(rawTx, nil)
			if err != nil {
				return err
			}
			_, err = broadTrans(signedTx)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// generateNewCntPrivKey 新生成一个主密钥，并派生cnt个密钥
func generateNewCntPrivKeys(cnt int) error {
	// 生成主密钥
	msk, _ := skroot.ChildPrivateKeyDeprive(uint32(len(mskSet)))
	err := importPrivkey(msk)
	if err != nil {
		return err
	}
	mskSet = append(mskSet, msk)
	var prikSetTemp []*KeyDerivation.PrivateKey
	var addressTemp []string
	//基于主密钥派生cnt个密钥
	for i := 0; i < cnt; i++ {
		key, _ := msk.ChildPrivateKeyDeprive(uint32(i))
		err := importPrivkey(key)
		if err != nil {
			return err
		}
		//更新密钥集及地址集
		prikSetTemp = append(prikSetTemp, key)
		address, err := KeyDerivation.GetAddressByPrivKey(key)
		if err != nil {
			return err
		}
		addressTemp = append(addressTemp, address)
	}
	prikSet = append(prikSet, prikSetTemp)
	addressSet = append(addressSet, addressTemp)
	return nil
}

// 更新地址持有UTXO的映射
func updateMapUTXOFromAddr() error {
	UTXObyAddress = map[string][]btcjson.ListUnspentResult{}
	allUTXO, err := client.ListUnspent()
	if err != nil {
		return err
	}
	for _, utxo := range allUTXO {
		UTXObyAddress[utxo.Address] = append(UTXObyAddress[utxo.Address], utxo)
	}
	return nil
}

// 发送隐蔽交易
func sendCovertTransaction(round, msgCnt int, splitMsg []string) ([]*chainhash.Hash, error) {
	mskId := round - 1
	var covertTxid []*chainhash.Hash
	//	构造addrcnt个隐蔽交易,每个交易只有1个输入1个输出
	for i := 0; i < msgCnt; i++ {
		// 创建交易
		rawTx, err := generateTrans(addressSet[mskId][i], addressSet[mskId+1][i])
		if err != nil {
			return nil, err
		}
		//	签名交易(嵌入消息)
		signedTx, err := signTrans(rawTx, &splitMsg[i])
		if err != nil {
			return nil, err
		}
		//	广播交易
		txId, err := broadTrans(signedTx)
		if err != nil {
			return nil, err
		}
		covertTxid = append(covertTxid, txId)
	}
	return covertTxid, nil
}
