package main

import (
	"bytes"
	"covertCommunication/Crypto"
	"covertCommunication/Key"
	"covertCommunication/RPC"
	"covertCommunication/Transaction"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"log"
	"strings"
	"unicode/utf8"
)

var (
	pkRoot   *Key.PublicKey //根公钥
	mpkSet   []*Key.PublicKey
	client   *rpcclient.Client //客户端
	keyAES   []byte
	netType  string
	kLeakStr string
	kLeak    *secp256k1.ModNScalar
)

// 已知根公钥以及泄露随机数
func init() {
	// 获取根公钥
	skRoot, _ := Key.GenerateMasterKey([]byte("initseed"))
	pkRoot = Key.EntirePublicKeyForPrivateKey(skRoot)
	kLeakStr = "leak Random"
	keyAES = []byte("1234567890123456")
	netType = "simnet"
	client = RPC.InitClient("localhost:28335", netType)
	kLeak = new(secp256k1.ModNScalar)
	kStrByte := []byte(kLeakStr)
	kLeak.SetByteSlice(kStrByte)

}
func main() {
	defer client.Shutdown()
	round := 1

	// 筛选泄露交易id
	leakId, mAddr, err := filterLeakTx(round)
	if err != nil {
		log.Fatal(err)
	}
	if leakId == nil {
		log.Fatal("can't get the leak transaction")
	}
	// 通过泄露交易提取主密钥
	msk, err := getPrivkeyFromTrans(round, kLeak, leakId, mAddr)
	if err != nil {
		fmt.Println(err)
	}
	// 验证提取的私钥地址是否正确
	//mskAddr, _ := Key.GetAddressByPrivateKey(msk, netType)
	//fmt.Println("msk address:", mskAddr)

	//	提取秘密消息
	covertMsg, err := extractCovertMsg(msk)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("the covert message is: %s", covertMsg)
}

// extractCovertMsg 基于主密钥不断派生子密钥筛选隐蔽交易，直到生成的密钥没有发起过交易
func extractCovertMsg(parentKey *Key.PrivateKey) (string, error) {
	covertMsg := ""
	for i := 0; ; i++ {
		// 计算地址，筛选泄露交易
		sk, err := parentKey.ChildPrivateKeyDeprive(uint32(i))
		if err != nil {
			return "", err
		}
		skAddr, err := Key.GetAddressByPrivateKey(sk, netType)
		if err != nil {
			return "", err
		}
		covertTxId, err := Transaction.FilterTransByInputaddr(client, skAddr)
		// 如果地址没有交易那么说明消息嵌入结束
		if covertTxId == nil {
			break
		}
		if err != nil {
			return "", err
		}
		// 获取交易签名，根据私钥提取随机数
		rawTx, err := client.GetRawTransaction(covertTxId)
		if err != nil {
			return "", err
		}
		signarute := Transaction.GetSignaruteFromTx(rawTx)
		hash, err := Transaction.GetHashFromTx(client, rawTx)
		if err != nil {
			return "", err
		}
		r := signarute.R()
		s := signarute.S()
		d := new(secp256k1.ModNScalar)
		d.SetByteSlice(sk.Key)
		k := recoverK(d, &r, &s, hash)

		// 转换后的字节0会出现在数组前部而实际数据出现在后部，会导致结束标志被分割，我们将0字节删除
		kByte := k.Bytes()
		kByteT := bytes.TrimLeft(kByte[:], "\x00")
		plainK, err := Crypto.Decrypt(kByteT, keyAES)
		if err != nil {
			return "", err
		}
		kStr := string(plainK)
		// 如果提取出的字符串没有意义，则需要计算s.negate()
		if !utf8.ValidString(kStr) {
			s.Negate()
			k := recoverK(d, &r, &s, hash)
			kByte = k.Bytes()
			kByteT = bytes.TrimLeft(kByte[:], "\x00")
			plainK, err := Crypto.Decrypt(kByteT, keyAES)
			if err != nil {
				return "", err
			}
			kStr = string(plainK)
		}
		covertMsg += kStr
		isEnd, msg := findEndFlag(covertMsg, "ENDEND")
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
func filterLeakTx(round int) (*chainhash.Hash, string, error) {
	mpkId := round - 1
	mpk, err := pkRoot.ChildPublicKeyDeprive(uint32(mpkId))
	if err != nil {
		return nil, "", err
	}
	mpkAddress, err := Key.GetAddressByPubKey(mpk, netType)
	if err != nil {
		return nil, "", err
	}
	leakTxId, err := Transaction.FilterTransByInputaddr(client, mpkAddress)
	if err != nil {
		return leakTxId, "", nil
	}
	return leakTxId, mpkAddress, err
}

// getPrivkeyFromTrans 根据泄露随机数提取泄露交易的密钥
func getPrivkeyFromTrans(round int, kleak *secp256k1.ModNScalar, txId *chainhash.Hash, addr string) (*Key.PrivateKey, error) {
	rawTx, _ := client.GetRawTransaction(txId)
	signature := Transaction.GetSignaruteFromTx(rawTx)
	hash, err := Transaction.GetHashFromTx(client, rawTx)
	if err != nil {
		return nil, err
	}
	r := signature.R()
	s := signature.S()
	d := recoverD(kleak, &r, &s, hash)
	//	将d转换为*KeyDerivation.PrivateKey格式
	priK := d.Bytes()
	privateKey := Key.GenerateEntireKey(pkRoot, priK[:], uint32(round-1))

	// 如果提取出私钥对应的地址不是实际地址，则需要计算s.negate()
	if addr2, _ := Key.GetAddressByPrivateKey(privateKey, netType); addr2 != addr {
		s.Negate()
		d = recoverD(kleak, &r, &s, hash)
		priK = d.Bytes()
		privateKey = Key.GenerateEntireKey(pkRoot, priK[:], uint32(round-1))
	}
	return privateKey, nil
}

// recoverK 已知私钥求随机数
func recoverK(d, r, s *secp256k1.ModNScalar, hash []byte) *secp256k1.ModNScalar {
	var k *secp256k1.ModNScalar
	var e secp256k1.ModNScalar
	e.SetByteSlice(hash)
	dr := new(secp256k1.ModNScalar).Mul2(d, r)
	sum := e.Add(dr)
	sinv := new(secp256k1.ModNScalar).InverseValNonConst(s)
	k = sinv.Mul(sum)
	return k
}

// recoverD 已知随机数求私钥
func recoverD(k, r, s *secp256k1.ModNScalar, hash []byte) *secp256k1.ModNScalar {
	var d *secp256k1.ModNScalar
	var e secp256k1.ModNScalar
	e.SetByteSlice(hash)

	ks := new(secp256k1.ModNScalar).Mul2(k, s)
	ksMinusE := ks.Add(e.Negate())

	sinr := new(secp256k1.ModNScalar).InverseValNonConst(r)
	d = sinr.Mul(ksMinusE)
	return d
}
