package main

import (
	"covertCommunication/KeyDerivation"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"log"
)

const btc = 100000000

var client *rpcclient.Client

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

func main() {
	initWallet()

	transfer(0, 15)
	//rawTx := generateTransFromUTXO("b5c9c14ac0c13123cf368136fd50293fe0dd9838384423da6a1a30ab0b26db0e", "SRMMzEu1AtnTfQorrE1CAiTQ2AdVgfiwp6", 10)
	//signTx, _ := signTrans(rawTx, nil)
	//broadTrans(signTx)
	client.Generate(1)
}

// 向第id个私钥下派生的cnt个地址各转入一个utxo
func transfer(id, cnt int) error {
	skroot, _ := KeyDerivation.GenerateMasterKey([]byte("initseed"))
	skid, _ := skroot.ChildPrivateKeyDeprive(uint32(id))
	importPrivkey(skid)

	utxos, _ := client.ListUnspent()
	num := 0
	for _, utxo := range utxos {
		if num == cnt {
			if utxo.Address != "SYZPAZEjXy7S4jbsUHqWUgv2FYomsR3RVS" || utxo.Amount != 50 {
				continue
			}
			destAddr, err := KeyDerivation.GetAddressByPrivKey(skid)
			sourceTxid := utxo.TxID
			rawTx := generateTransFromUTXO(sourceTxid, destAddr, utxo.Amount)
			signTx, err := signTrans(rawTx, nil)
			if err != nil {
				log.Fatalf("Error: %s", err)
			}
			broadTrans(signTx)
			break
		}
		if utxo.Address != "SYZPAZEjXy7S4jbsUHqWUgv2FYomsR3RVS" || utxo.Amount != 50 {
			continue
		}
		skidnum, _ := skid.ChildPrivateKeyDeprive(uint32(num))
		err := importPrivkey(skidnum)

		destAddr, err := KeyDerivation.GetAddressByPrivKey(skidnum)
		if err != nil {
			return err
		}
		sourceTxid := utxo.TxID
		rawTx := generateTransFromUTXO(sourceTxid, destAddr, utxo.Amount)
		signTx, err := signTrans(rawTx, nil)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		broadTrans(signTx)
		num++
	}
	return nil
}
func importPrivkey(key *KeyDerivation.PrivateKey) error {
	prikWIF, err := KeyDerivation.ToWIF(key.Key)
	if err != nil {
		return err
	}
	wif, _ := btcutil.DecodeWIF(prikWIF)
	err = client.ImportPrivKey(wif)
	if err != nil {
		return err
	}
	return nil
}

// 生成sourceAddr到destAddr的原始交易（将UTXO全部转给目标地址，没有交易费）
func generateTransFromUTXO(txid, destAddr string, amount float64) *wire.MsgTx {
	// 构造输入
	var inputs []btcjson.TransactionInput
	inputs = append(inputs, btcjson.TransactionInput{
		Txid: txid,
		Vout: 0,
	})
	//	构造输出
	outAddr, _ := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	outputs := map[btcutil.Address]btcutil.Amount{
		outAddr: btcutil.Amount((amount - 1) * btc),
	}
	//	创建交易
	rawTx, err := client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		log.Fatalf("Error creating raw transaction: %v", err)
	}
	return rawTx
}

// 签名交易，嵌入秘密消息
func signTrans(rawTx *wire.MsgTx, embedMsg *string) (*wire.MsgTx, error) {
	signedTx, complete, err, _ := client.SignRawTransaction(rawTx, embedMsg)
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}
	if !complete {
		log.Fatalf("Transaction signing incomplete")
	}
	// 保存签名
	//if embedMsg == nil {
	//	sig := hex.EncodeToString(signedTx.TxIn[0].SignatureScript)
	//	sign, ok := DataAnalysis.GetSignatureFromHex(sig)
	//	if !ok {
	//		return nil, errors.New("get signature error")
	//	}
	//	err = DataAnalysis.AppendSignature(sign, "DataAnalysis/DataSet/NormalSig_10.xlsx")
	//	if err != nil {
	//		return nil, err
	//	}
	//}
	return signedTx, nil
}

// 广播交易
func broadTrans(signedTx *wire.MsgTx) string {
	txHash, err := client.SendRawTransaction(signedTx, false)
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}
	return txHash.String()
}
