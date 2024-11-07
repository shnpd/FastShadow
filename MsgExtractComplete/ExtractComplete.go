package main

import (
	"covertCommunication/KeyDerivation"
	"covertCommunication/Share"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"strings"
)

var (
	pkroot   *KeyDerivation.PublicKey //根公钥
	kleakStr string                   //泄露随机数(字符串格式)
	mpkSet   []*KeyDerivation.PublicKey
	client   *rpcclient.Client //客户端
)

// 已知根公钥以及泄露随机数
func init() {
	skroot, _ := KeyDerivation.GenerateMasterKey([]byte("initseed"))
	pkroot = KeyDerivation.EntirePublicKeyForPrivateKey(skroot)
	hash1, _ := chainhash.NewHashFromStr("df1914d88d5e2d33285d73a142f56257e53d658872aaa0a20dd8ca3c1c19a221")
	hash2, _ := chainhash.NewHashFromStr("88e91c3ee1e4381a800224665babbe50760ddd9214bf28dc9a9e95d5f811cf28")
	hash3, _ := chainhash.NewHashFromStr("093f13fdccce42d6b5c219fed09ce25b798c59157019d5477127a6351df35361")
	hash4, _ := chainhash.NewHashFromStr("4988112230ab4f55c3df282401c19c6784c45ac4a090765a2bc9b0b70ac5c464")
	hash5, _ := chainhash.NewHashFromStr("15eee069d7b8da90f6c0c31665d216c1fad1df3537d34924ed8e1016cd74617a")
	hash6, _ := chainhash.NewHashFromStr("7d2cf71aa7db4765d4228da14d98ba20bd210ca3d74c2a2a540e2a811957eee8")

	Share.IsTxSignOver = map[chainhash.Hash]bool{
		*hash1: false,
		*hash2: true,
		*hash3: true,
		*hash4: true,
		*hash5: false,
		*hash6: true,
	}
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
	err := client.WalletPassphrase("ts0", 6000)
	if err != nil {
		fmt.Println(err)
	}
}
func main() {

	initWallet()
	defer client.Shutdown()
	round := 1

	kleak := new(secp256k1.ModNScalar)
	kleakStr = "leak Random"
	k_str_byte := []byte(kleakStr)
	kleak.SetByteSlice(k_str_byte)
	// 过滤泄露交易id
	leakId, err := filterLeakTx(round)
	if err != nil {
		fmt.Println(err)
	}

	// 通过泄露交易提取主密钥
	msk, err := getPrivkeyFromTrans(round, kleak, leakId)
	mskAddr, _ := KeyDerivation.GetAddressByPrivKey(msk)
	fmt.Println("msk address:", mskAddr)
	if err != nil {
		fmt.Println(err)
	}
	//	提取秘密消息
	covertMsg, err := extractCovertMsg(msk)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("the covert message is: %s", covertMsg)
}

// extractCovertMsg 基于主密钥不断派生子密钥筛选隐蔽交易，直到生成的密钥没有发起过交易
func extractCovertMsg(parentKey *KeyDerivation.PrivateKey) (string, error) {
	covertMsg := ""
	for i := 0; ; i++ {
		sk, err := parentKey.ChildPrivateKeyDeprive(uint32(i))
		if err != nil {
			return "", err
		}
		skAddr, err := KeyDerivation.GetAddressByPrivKey(sk)
		if err != nil {
			return "", err
		}
		covertTxId, err := filterTransByInputaddr(skAddr)
		if covertTxId == nil {
			break
		}
		if err != nil {
			return "", err
		}
		rawTx, _ := client.GetRawTransaction(covertTxId)
		signarute := getSignaruteFromTx(rawTx)
		hash, err := getHashFromTx(rawTx)
		if err != nil {
			return "", err
		}
		r := signarute.R()
		s := signarute.S()
		d := new(secp256k1.ModNScalar)
		d.SetByteSlice(sk.Key)
		k := recoverK(d, &r, &s, hash)
		kByte := k.Bytes()
		kStr := string(kByte[:])
		covertMsg += kStr
		isEnd, msg := findEndFlag(covertMsg, "end")
		if isEnd {
			return msg, nil
		}
	}
	return covertMsg, nil
}

// findEndFlag 判断当前提取的字符串是否包含结束标志，如果包含则截取结束标志之前的内容并返回true
func findEndFlag(str, end string) (bool, string) {
	endIndex := strings.Index(str, end)
	if endIndex == -1 {
		return false, ""
	} else {
		return true, str[:endIndex]
	}
}

// filterLeakTx 筛选泄露交易，第round轮通信使用第round-1个主公钥
func filterLeakTx(round int) (*chainhash.Hash, error) {
	mpkId := round - 1
	mpk, err := pkroot.ChildPublicKeyDeprive(uint32(mpkId))
	if err != nil {
		return nil, err
	}
	mpkAddress, err := KeyDerivation.GetAddressByPubKey(mpk)
	if err != nil {
		return nil, err
	}
	leakTxId, err := filterTransByInputaddr(mpkAddress)
	if err != nil {
		return leakTxId, nil
	}
	return leakTxId, err
}

// getPrivkeyFromTrans 根据泄露随机数提取泄露交易的密钥
func getPrivkeyFromTrans(round int, kleak *secp256k1.ModNScalar, txId *chainhash.Hash) (*KeyDerivation.PrivateKey, error) {
	rawTx, _ := client.GetRawTransaction(txId)
	signature := getSignaruteFromTx(rawTx)
	hash, err := getHashFromTx(rawTx)
	if err != nil {
		return nil, err
	}
	r := signature.R()
	s := signature.S()
	d := recoverD(kleak, &r, &s, hash)
	//	将d转换为*KeyDerivation.PrivateKey格式
	priK := d.Bytes()
	privateKey := KeyDerivation.GenerateEntireParentKey(pkroot, priK[:], uint32(round-1))
	return privateKey, nil
}

// getSignaruteFromTx 提取交易签名
func getSignaruteFromTx(rawTx *btcutil.Tx) *ecdsa.Signature {
	signatureScript := hex.EncodeToString(rawTx.MsgTx().TxIn[0].SignatureScript)
	sig := getsigFromHex(signatureScript)
	r := sig.R()
	s := sig.S()
	if Share.IsTxSignOver[*rawTx.Hash()] {
		s.Negate()
	}
	sigOrigin := ecdsa.NewSignature(&r, &s)
	return sigOrigin
}

// getHashFromTx 提取交易签名数据
func getHashFromTx(rawTx *btcutil.Tx) ([]byte, error) {
	var script []byte
	var hashType txscript.SigHashType
	tx := new(wire.MsgTx)
	var idx int
	idx = 0
	tx = rawTx.MsgTx()
	hashType = 1
	script = getScript(rawTx.MsgTx(), client)
	hash, err := txscript.CalcSignatureHash(script, hashType, tx, idx)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// TODO:可优化
// filterTransByInputaddr 根据输入地址筛选交易，默认一个地址只参与一个交易
func filterTransByInputaddr(addr string) (*chainhash.Hash, error) {
	transactions, _ := client.ListTransactionsCount("*", 99999)
	// 遍历所有交易依次筛选
	for _, v := range transactions {
		txId, err := chainhash.NewHashFromStr(v.TxID)
		// coinbase交易没有输入
		if v.Generated {
			continue
		}
		// 获取交易的输入
		inputUTXO, err := getInputUTXO(txId)
		if err != nil {
			return nil, err
		}
		// 根据输入utxo提取输入地址
		for _, utxo := range inputUTXO {
			// 产生这个utxo的交易id
			utxoHash := utxo.Hash
			// utxo在交易中的序号
			utxoIndex := utxo.Index
			// 获取前置交易
			previousTrans, _ := client.GetTransaction(&utxoHash)
			var addrTemp string
			// 从details找到对应的vout，（每一个输出都会在details中插入两条记录，一个send类型，一个receive类型，coinbase交易只有一个为generate类型）
			if previousTrans.Details[0].Category == "generate" {
				continue
			}
			addrTemp = previousTrans.Details[2*utxoIndex+1].Address
			// 交易的输入地址包含目标地址
			if err != nil {
				return nil, err
			}
			if addrTemp == addr {
				return txId, nil
			}
		}
	}
	return nil, fmt.Errorf("not exist transaction with input address:%s", addr)
}
