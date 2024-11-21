// Package Derivation 密钥派生的相关操作
package Key

import (
	"covertCommunication/Crypto"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/mndrix/btcutil"
)

var (
	//定义曲线
	curve = btcutil.Secp256k1()
	//定义曲线参数
	curveParams = curve.Params()
	//	定义网络类型
	mainPublicWalletVersion, _  = hex.DecodeString("0488B21E")
	mainPrivateWalletVersion, _ = hex.DecodeString("0488ADE4")
	testPublicWalletVersion, _  = hex.DecodeString("043587CF")
	testPrivateWalletVersion, _ = hex.DecodeString("04358394")
)

// PrivateKey 定义公私钥格式
type PrivateKey struct {
	Version      []byte // 4 bytes
	Depth        byte
	FatherFinger []byte // 4 bytes
	ChildNumber  []byte // 4 bytes
	Chaincode    []byte // 32 bytes
	Key          []byte // 33 bytes
}
type PublicKey struct {
	Version      []byte
	Depth        byte
	FatherFinger []byte
	ChildNumber  []byte
	Chaincode    []byte
	Key          []byte
}

// GenerateMasterKey 基于密钥种子生成主密钥
func GenerateMasterKey(seed []byte) (*PrivateKey, error) {
	hmacSeed := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := hmacSeed.Write(seed)
	if err != nil {
		return nil, err
	}
	I := hmacSeed.Sum(nil)
	masterPrivateKey := I[:32]
	masterPrivateKeyChaincode := I[32:]
	err = ValidatePrivateKey(masterPrivateKey)
	if err != nil {
		return nil, err
	}
	key := &PrivateKey{
		Version:      testPrivateWalletVersion,
		Depth:        0x0,
		FatherFinger: []byte{0x00, 0x00, 0x00, 0x00},
		ChildNumber:  []byte{0x00, 0x00, 0x00, 0x00},
		Chaincode:    masterPrivateKeyChaincode,
		Key:          masterPrivateKey,
	}
	return key, nil
}

// ChildPrivateKeyDeprive 私钥派生
func (key *PrivateKey) ChildPrivateKeyDeprive(childIndex uint32) (*PrivateKey, error) {
	childIndexBytes := serializeUint32(childIndex)
	data := PublicKeyForPrivateKey(key.Key)
	data = append(data, childIndexBytes...)
	myHmac := hmac.New(sha512.New, key.Chaincode)
	_, err := myHmac.Write(data)
	if err != nil {
		return nil, err
	}
	I := myHmac.Sum(nil)
	ki := addPrivateKeys(I[:32], key.Key)
	err = ValidateDeprivPrivateKey(I[:32], ki)
	if err != nil {
		return nil, err
	}
	childKey := &PrivateKey{
		Version:      testPrivateWalletVersion,
		FatherFinger: Crypto.Hash160(PublicKeyForPrivateKey(key.Key))[:4],
		ChildNumber:  childIndexBytes,
		Chaincode:    I[32:],
		Depth:        key.Depth + 1,
		Key:          ki,
	}
	return childKey, nil
}

// ChildPublicKeyDeprive 公钥派生
func (key *PublicKey) ChildPublicKeyDeprive(childIndex uint32) (*PublicKey, error) {
	childIndexBytes := serializeUint32(childIndex)
	data := key.Key
	data = append(data, childIndexBytes...)
	myHmac := hmac.New(sha512.New, key.Chaincode)
	_, err := myHmac.Write(data)
	if err != nil {
		return nil, err
	}
	I := myHmac.Sum(nil)
	Ki := addPublicKeys(PublicKeyForPrivateKey(I[:32]), key.Key)
	err = ValidateDeprivPublicKey(I[:32], Ki)
	if err != nil {
		return nil, err
	}
	childKey := &PublicKey{
		Version:      testPublicWalletVersion,
		FatherFinger: Crypto.Hash160(key.Key)[:4],
		ChildNumber:  childIndexBytes,
		Chaincode:    I[32:],
		Depth:        key.Depth + 1,
		Key:          Ki,
	}
	return childKey, nil
}

// 从start开始派生cnt个私钥
func (msk *PrivateKey) DeprivCntKeys(client *rpcclient.Client, start, cnt int, netType string) ([]*PrivateKey, error) {
	var keySet []*PrivateKey
	//基于主密钥派生cnt个密钥
	for i := start; i < start+cnt; i++ {
		key, _ := msk.ChildPrivateKeyDeprive(uint32(i))
		err := ImportKey(client, key, netType)
		if err != nil {
			return nil, err
		}
		//更新密钥集及地址集
		keySet = append(keySet, key)
	}
	return keySet, nil
}

// PublicKeyForPrivateKey 返回私钥对应的公钥，只返回密钥
func PublicKeyForPrivateKey(key []byte) []byte {
	return serializePub(point(key))
}

// EntirePublicKeyForPrivateKey 返回私钥对应的公钥，返回完整格式
func EntirePublicKeyForPrivateKey(priv *PrivateKey) *PublicKey {
	ret := &PublicKey{
		Version:      testPublicWalletVersion,
		Depth:        priv.Depth,
		FatherFinger: priv.FatherFinger,
		ChildNumber:  priv.ChildNumber,
		Chaincode:    priv.Chaincode,
		Key:          PublicKeyForPrivateKey(priv.Key),
	}
	return ret
}

// 将单独的私钥转换为标准的密钥派生的私钥格式
func GenerateEntireKey(fatherKey *PublicKey, priKey []byte, id uint32) *PrivateKey {
	childIndexBytes := serializeUint32(id)
	data := fatherKey.Key
	data = append(data, childIndexBytes...)
	myHmac := hmac.New(sha512.New, fatherKey.Chaincode)
	myHmac.Write(data)
	I := myHmac.Sum(nil)
	Chaincode := I[32:]
	key := &PrivateKey{
		Version:      testPrivateWalletVersion,
		FatherFinger: Crypto.Hash160(fatherKey.Key)[:4],
		ChildNumber:  childIndexBytes,
		Chaincode:    Chaincode,
		Depth:        0x1,
		Key:          priKey,
	}
	return key
}

// GenerateMsk 生成并导入第id个主密钥
func GenerateMsk(client *rpcclient.Client, skroot *PrivateKey, id int, netType string) (*PrivateKey, error) {
	msk, _ := skroot.ChildPrivateKeyDeprive(uint32(id))
	err := ImportKey(client, msk, netType)
	if err != nil {
		return nil, err
	}
	return msk, nil
}
