package Transfer

import (
	"covertCommunication/Key"
	"covertCommunication/RPC"
	"covertCommunication/Transaction"
	"github.com/btcsuite/btcd/rpcclient"
	"log"
	"time"
)

const btc = 100000000

var (
	netType    string
	client     *rpcclient.Client
	miningAddr string
)

func init() {
	netType = "simnet"
	client = RPC.InitClient("localhost:28335", netType)
	miningAddr = "SXXfUx9qdszdhEgFJMq5625co9JrqbeRBv"
	client.WalletPassphrase("ts0", 6000)

}
func main() {
	//for i := 0; i < 10; i++ {
	//	client.GetNewAddress("default")
	//}
	//time.Sleep(time.Second * 1)
	//client.Generate(299)
	//time.Sleep(time.Second * 3)
	//
	//err := transfer(0, 10)
	//if err != nil {
	//	log.Fatal(err)
	//}

	client.Generate(1)
	//rawTx := generateTransFromUTXO("b5c9c14ac0c13123cf368136fd50293fe0dd9838384423da6a1a30ab0b26db0e", "SRMMzEu1AtnTfQorrE1CAiTQ2AdVgfiwp6", 10)
	//signTx, _ := signTrans(rawTx, nil)
	//broadTrans(signTx)
}

// 从挖矿地址向第id个私钥下派生的cnt个地址各转入一个utxo
func Transfer(id, cnt int) error {
	skroot, _ := Key.GenerateMasterKey([]byte("initseed"))
	msk, _ := skroot.ChildPrivateKeyDeprive(uint32(id))
	err := Key.ImportKey(client, msk, netType)
	if err != nil {
		return err
	}
	utxos, _ := client.ListUnspent()
	num := 0
	for _, utxo := range utxos {
		if utxo.Address != miningAddr {
			continue
		}
		if num == cnt {
			// 最后向主密钥转入utxo用于发送泄露交易
			mskAddr, err := Key.GetAddressByPrivateKey(msk, netType)
			if err != nil {
				log.Fatal(err)
			}
			_, err = Transaction.EntireSendTrans(client, miningAddr, mskAddr, 1, nil)
			if err != nil {
				return err
			}
			break
		}
		sk, err := msk.ChildPrivateKeyDeprive(uint32(num))
		if err != nil {
			return err
		}
		err = Key.ImportKey(client, sk, netType)
		if err != nil {
			return err
		}
		destAddr, err := Key.GetAddressByPrivateKey(sk, netType)
		if err != nil {
			return err
		}
		_, err = Transaction.EntireSendTrans(client, miningAddr, destAddr, 1, nil)
		if err != nil {
			return err
		}
		num++
		time.Sleep(500 * time.Millisecond)
	}
	client.Generate(1)
	return nil
}
