// 基于比特币BIP32提案实现密钥派生
package KeyDerivation

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/mndrix/btcutil" //椭圆曲线
	"math/big"
)

var (
	//定义曲线
	curve = btcutil.Secp256k1()
	//定义曲线参数
	curveParams = curve.Params()
	//	定义网络类型
	netType = "simnet"
)

var (
	mainPublicWalletVersion, _  = hex.DecodeString("0488B21E")
	mainPrivateWalletVersion, _ = hex.DecodeString("0488ADE4")
	testPublicWalletVersion, _  = hex.DecodeString("043587CF")
	testPrivateWalletVersion, _ = hex.DecodeString("04358394")
)

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

// 基于密钥种子生成主密钥
func GenerateMasterKey(seed []byte) (*PrivateKey, error) {
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, err := hmac.Write(seed)
	if err != nil {
		return nil, err
	}
	I := hmac.Sum(nil)
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

// 验证种子生成的主密钥是否合法
func ValidatePrivateKey(key []byte) error {
	if len(key) != 32 {
		return errors.New("invalid seed")
	}
	if fmt.Sprintf("%x", key) == "00000000000000000000000000000000" {
		return errors.New("invalid seed")
	}
	if bytes.Compare(key, curveParams.N.Bytes()) >= 0 {
		return errors.New("invalid seed")
	}
	return nil
}

// 验证派生私钥是否合法
func ValidateDeprivPrivateKey(Il []byte, ki []byte) error {
	if bytes.Compare(Il, curveParams.N.Bytes()) >= 0 {
		return errors.New("invalid key")
	}
	if new(big.Int).SetBytes(ki).Cmp(big.NewInt(0)) == 0 {
		return errors.New("invalid key")
	}
	return nil

}

// 验证派生公钥是否合法
func ValidateDeprivPublicKey(Il []byte, Ki []byte) error {
	if bytes.Compare(Il, curveParams.N.Bytes()) >= 0 {
		return errors.New("invalid key")
	}
	x, y := deserializePub(Ki)
	if x.Sign() == 0 || y.Sign() == 0 {
		return errors.New("Invalid public key")
	}
	return nil
}

// 私钥派生
func (key *PrivateKey) ChildPrivateKeyDeprive(childIndex uint32) (*PrivateKey, error) {
	childIndexBytes := serializeUint32(childIndex)
	data := PublicKeyForPrivateKey(key.Key)
	data = append(data, childIndexBytes...)
	hmac := hmac.New(sha512.New, key.Chaincode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	I := hmac.Sum(nil)
	ki := addPrivateKeys(I[:32], key.Key)
	err = ValidateDeprivPrivateKey(I[:32], ki)
	if err != nil {
		return nil, err
	}
	childKey := &PrivateKey{
		Version:      testPrivateWalletVersion,
		FatherFinger: hash160(PublicKeyForPrivateKey(key.Key))[:4],
		ChildNumber:  childIndexBytes,
		Chaincode:    I[32:],
		Depth:        key.Depth + 1,
		Key:          ki,
	}
	return childKey, nil
}

// 公钥派生
func (key *PublicKey) ChildPublicKeyDeprive(childIndex uint32) (*PublicKey, error) {
	childIndexBytes := serializeUint32(childIndex)
	data := key.Key
	data = append(data, childIndexBytes...)
	hmac := hmac.New(sha512.New, key.Chaincode)
	_, err := hmac.Write(data)
	if err != nil {
		return nil, err
	}
	I := hmac.Sum(nil)
	Ki := addPublicKeys(PublicKeyForPrivateKey(I[:32]), key.Key)
	err = ValidateDeprivPublicKey(I[:32], Ki)
	if err != nil {
		return nil, err
	}
	childKey := &PublicKey{
		Version:      testPublicWalletVersion,
		FatherFinger: hash160(key.Key)[:4],
		ChildNumber:  childIndexBytes,
		Chaincode:    I[32:],
		Depth:        key.Depth + 1,
		Key:          Ki,
	}
	return childKey, nil
}

// 序列化私钥
func (key *PrivateKey) SerializePriv() []byte {
	// Private keys should be prepended with a single null byte
	keyBytes := key.Key
	keyBytes = append([]byte{0x0}, keyBytes...)

	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	_, err := buffer.Write(key.Version)
	if err != nil {
		return nil
	}
	err = buffer.WriteByte(key.Depth)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(key.FatherFinger)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(key.ChildNumber)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(key.Chaincode)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(keyBytes)
	if err != nil {
		return nil
	}
	// Append the standard doublesha256 checksum
	serializedKey := addChecksumToBytes(buffer.Bytes())
	return serializedKey
}

// 序列化公钥
func (key *PublicKey) SerializePub() []byte {
	// Private keys should be prepended with a single null byte
	keyBytes := key.Key
	// Write fields to buffer in order
	buffer := new(bytes.Buffer)
	_, err := buffer.Write(key.Version)
	if err != nil {
		return nil
	}
	err = buffer.WriteByte(key.Depth)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(key.FatherFinger)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(key.ChildNumber)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(key.Chaincode)
	if err != nil {
		return nil
	}
	_, err = buffer.Write(keyBytes)
	if err != nil {
		return nil
	}
	// Append the standard doublesha256 checksum
	serializedKey := addChecksumToBytes(buffer.Bytes())
	return serializedKey
}

func NewSeed() ([]byte, error) {
	// Well that easy, just make go read 256 random bytes into a slice
	s := make([]byte, 256)
	_, err := rand.Read(s)
	return s, err
}
