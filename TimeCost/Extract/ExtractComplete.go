// 该文件与MsgExtractComplete/ExtractComplete.go 基本一致，但是为了模拟测试主网下的时间延迟，
// 我们通过调用第三方api的方法来根据输入地址筛选交易，具体表现为使用filterTransByInputaddrByAPI()代替filterTransByInputaddr()
package main

import (
	"bytes"
	"covertCommunication/KeyDerivation"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
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

// 循环执行十次每次都从第0组地址提取秘密消息
func main() {
	initWallet()
	defer client.Shutdown()
	round := 1
	for i := 0; i < 10; i++ {
		start := time.Now()
		kleak := new(secp256k1.ModNScalar)
		kleakStr = "leak Random"
		k_str_byte := []byte(kleakStr)
		kleak.SetByteSlice(k_str_byte)
		// 过滤泄露交易id
		leakId, mAddr, err := filterLeakTx(round)

		if leakId == nil {
			fmt.Println("can't get the leak transaction")
		}
		if err != nil {
			fmt.Println(err)
		}

		// 通过泄露交易提取主密钥
		msk, err := getPrivkeyFromTrans(round, kleak, leakId, mAddr)
		if err != nil {
			fmt.Println(err)
		}
		//	提取秘密消息
		covertMsg, err := extractCovertMsg(msk)
		if err != nil {
			fmt.Println(err)
		}
		duration := time.Since(start)
		if i == 0 {
			fmt.Printf("the covert message is: %s\n", covertMsg)
		}
		fmt.Println(duration)

	}

}

// extractCovertMsg 基于主密钥不断派生子密钥筛选隐蔽交易，直到生成的密钥没有发起过交易
func extractCovertMsg(parentKey *KeyDerivation.PrivateKey) (string, error) {
	covertMsg := ""
	for i := 0; ; i++ {
		// 计算地址，筛选泄露交易
		sk, err := parentKey.ChildPrivateKeyDeprive(uint32(i))
		if err != nil {
			return "", err
		}
		skAddr, err := KeyDerivation.GetAddressByPrivKey(sk)
		if err != nil {
			return "", err
		}
		covertTxId, err := filterTransByInputaddrByAPI(skAddr)
		// 如果地址没有交易那么说明消息嵌入结束
		if covertTxId == nil {
			break
		}
		if err != nil {
			return "", err
		}
		// 获取交易签名，根据私钥提取随机数
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
		// 转换后的字节0会出现在数组前部而实际数据出现在后部，会导致结束标志被分割，我们将0字节删除
		kByte := k.Bytes()
		kByteT := bytes.TrimLeft(kByte[:], "\x00")
		kStr := string(kByteT)
		// 如果提取出的字符串没有意义，则需要计算s.negate()
		if !utf8.ValidString(kStr) {
			s.Negate()
			k := recoverK(d, &r, &s, hash)
			kByte = k.Bytes()
			kByteT = bytes.TrimLeft(kByte[:], "\x00")
			kStr = string(kByteT)
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
	mpk, err := pkroot.ChildPublicKeyDeprive(uint32(mpkId))
	if err != nil {
		return nil, "", err
	}
	mpkAddress, err := KeyDerivation.GetAddressByPubKey(mpk)
	if err != nil {
		return nil, "", err
	}
	leakTxId, err := filterTransByInputaddrByAPI(mpkAddress)
	if err != nil {
		return leakTxId, "", nil
	}
	return leakTxId, mpkAddress, err
}

// getPrivkeyFromTrans 根据泄露随机数提取泄露交易的密钥
func getPrivkeyFromTrans(round int, kleak *secp256k1.ModNScalar, txId *chainhash.Hash, addr string) (*KeyDerivation.PrivateKey, error) {
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

	// 如果提取出私钥对应的地址不是实际地址，则需要计算s.negate()
	if addr2, _ := KeyDerivation.GetAddressByPrivKey(privateKey); addr2 != addr {
		s.Negate()
		d = recoverD(kleak, &r, &s, hash)
		priK = d.Bytes()
		privateKey = KeyDerivation.GenerateEntireParentKey(pkroot, priK[:], uint32(round-1))
	}
	return privateKey, nil
}

// getSignaruteFromTx 提取交易签名
func getSignaruteFromTx(rawTx *btcutil.Tx) *ecdsa.Signature {
	signatureScript := hex.EncodeToString(rawTx.MsgTx().TxIn[0].SignatureScript)
	sig := getsigFromHex(signatureScript)
	r := sig.R()
	s := sig.S()
	//if Share.IsTxSignOver[*rawTx.Hash()] {
	//	s.Negate()
	//}
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

// filterTransByInputaddrByAPI 模拟主网查询请求，任意发送一个地址的请求，直接返回隐蔽交易的id（本地simnet网络无法调用第三方api）
func filterTransByInputaddrByAPI(addr string) (*chainhash.Hash, error) {
	url := fmt.Sprintf("https://api.3xpl.com/bitcoin/address/%s?token=3A0_t3st3xplor3rpub11cb3t4efcd21748a5e&data=events", addr)
	resp, err := http.Get(url)
	if resp.StatusCode != 200 {
		log.Fatalf("请求失败：%s", resp.Status)
		return nil, err
	}
	defer resp.Body.Close()

	// 模拟由api返回交易id
	switch addr {
	case "SRMMzEu1AtnTfQorrE1CAiTQ2AdVgfiwp6":
		hash, _ := chainhash.NewHashFromStr("b559e5529a7184cc388fef50f2ce55336ce39740987507c4bb167b571f6ad2bc")
		return hash, nil
	case "SiGGuKwQ2WP1uZ63TBVk1E6mb3qPyqrnEg":
		hash, _ := chainhash.NewHashFromStr("b6a0443e58720551fece4b601b559cfc035f895fc139ba1ea22c1c9667770fb9")
		return hash, nil
	case "SNb2cVFfzTW4ecMyRg7DncL4vKbFka9mGA":
		hash, _ := chainhash.NewHashFromStr("dfec5be7e3becb59296f1e277e679663c98d3e0521a8d612403d38f263a03711")
		return hash, nil
	case "SjJaJhDBcWUW2x8UUiXrucpqZMW4GfEbFn":
		hash, _ := chainhash.NewHashFromStr("82e251cb5ff9bab1ff284d5d27b28f24b6b08844234ab2ec55ca9f0b77bc18cd")
		return hash, nil
	case "STGeYnmKs1XRRUdY5xBWQgkDe12XM69uPR":
		hash, _ := chainhash.NewHashFromStr("4e9e70c5592a2a800f27d7a50c8474e38c326c3433d0ce479d369b43de4513ec")
		return hash, nil
	case "SZKehtZnRaRD9xX3TWzPaJ1noWJPewsvbz":
		hash, _ := chainhash.NewHashFromStr("eb8c5843d1c3acace9ddd046a96e0f4183f89a1ca186d8e806a83c26a52120a8")
		return hash, nil
	case "Sbw2ujZf3zPw1xqKEFdKsYnfCKWZLodjHn":
		hash, _ := chainhash.NewHashFromStr("a55d7f5b10a600dff9f431acb07716ded950ba10a470678cc689cb3174e7b008")
		return hash, nil
	case "ScnZkmpzFhkTqDggW58ngUrBZQ6kz6Yx5Y":
		hash, _ := chainhash.NewHashFromStr("1df500db9adbfb1b806abe3f5e7c883e7553e48b8c8fa5d9058e4479b79b598b")
		return hash, nil
	case "SkcyqqePBo4YBPbkm3HsFXuCXnmK9XmVCj":
		hash, _ := chainhash.NewHashFromStr("e671bb55faa4bd5b3979ffef172a982dfec17902b0e0dbc8de4448c008f39add")
		return hash, nil
	case "ScECtJUTBteEKBh8s5ZNZkeUa6Rutz9vK8":
		hash, _ := chainhash.NewHashFromStr("88022519083fee764f6c737bfdc704f372caf48223d4a5094c5ae118f9ce8079")
		return hash, nil
	case "SS6TEYptYhuDDwPvJEtbfYRdPGVxNKEDY9":
		hash, _ := chainhash.NewHashFromStr("1ff3be006e37cb1962956d9a9ae0ec8ea1c2fe75f3e114b6e7c153e7a34cebd4")
		return hash, nil
	case "Sft65bpbVnAoBYN3d78YXr2pHHVRjYDmdv":
		hash, _ := chainhash.NewHashFromStr("9630ba724859685d19852d9b6e84892dff64c098990796e017716d6b06efc09b")
		return hash, nil
	case "Sc4DW59hYDmyz8ZNZZdR7wSNkZt99XrydU":
		hash, _ := chainhash.NewHashFromStr("1a2134cb448864b232fc00d3e954fb0b845a90cb36fe8be8d749a6d89571401b")
		return hash, nil
	}
	return nil, errors.New("can't get trans by input address")
}
