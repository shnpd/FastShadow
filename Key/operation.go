// Package Key 密钥相关操作：派生密钥，密钥转换等
package Key

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/rpcclient"
	"math/big"
)

// point(p):返回secp256k1基点与整数p进行EC点乘法(重复应用EC群运算)得到的坐标对。
func point(p []byte) (*big.Int, *big.Int) {
	return curve.ScalarBaseMult(p)
}

// addPrivateKeys 私钥相加
func addPrivateKeys(key1 []byte, key2 []byte) []byte {
	var key1Int big.Int
	var key2Int big.Int
	key1Int.SetBytes(key1)
	key2Int.SetBytes(key2)

	key1Int.Add(&key1Int, &key2Int)
	key1Int.Mod(&key1Int, curve.Params().N)

	b := key1Int.Bytes()
	if len(b) < 32 {
		extra := make([]byte, 32-len(b))
		b = append(extra, b...)
	}
	return b
}

// addPublicKeys 公钥相加，先反序列化为坐标对，将坐标对相加后再序列化
func addPublicKeys(key1 []byte, key2 []byte) []byte {
	x1, y1 := deserializePub(key1)
	x2, y2 := deserializePub(key2)
	return serializePub(curve.Add(x1, y1, x2, y2))
}
func ImportKey(client *rpcclient.Client, key *PrivateKey, netType string) error {
	prikWIF, err := Key2WIF(key.Key, netType)
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
