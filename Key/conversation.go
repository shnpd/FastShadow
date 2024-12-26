package Key

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// WIF2Key 将 WIF 格式转换为私钥
func WIF2Key(wif string) ([]byte, string, error) {
	// 解码 Base58
	wifBytes := base58.Decode(wif)
	// 检查 WIF 长度
	if len(wifBytes) != 37 {
		return nil, "", fmt.Errorf("invalid WIF length")
	}
	// 提取网络字节和私钥
	networkByte := wifBytes[0]
	privateKey := wifBytes[1:33]
	checksum := wifBytes[33:]
	// 计算校验和
	checksumCalculated := sha256.Sum256(wifBytes[:33])        // 第一次SHA-256
	checksumCalculated = sha256.Sum256(checksumCalculated[:]) // 第二次SHA-256
	checksumExpected := checksumCalculated[:4]                // 取前4字节作为校验和
	// 验证校验和
	if !bytes.Equal(checksum, checksumExpected) {
		return nil, "", fmt.Errorf("invalid checksum")
	}
	// 根据网络字节确定网络类型
	var net string
	switch networkByte {
	case 0x80:
		net = "mainnet"
	case 0xEF:
		net = "testnet"
	case 0x64:
		net = "simnet"
	default:
		return nil, "", fmt.Errorf("unknown network byte")
	}
	return privateKey, net, nil
}

// GetAddressByWIF 根据wif格式私钥获取对应的地址
func GetAddressByWIF(wif string, netType string) (string, error) {
	var param chaincfg.Params
	switch netType {
	case "simnet":
		param = chaincfg.SimNetParams
	case "testnet":
		param = chaincfg.TestNet3Params
	case "mainnet":
		param = chaincfg.MainNetParams
	default:
		return "", errors.New("error netType")
	}
	// 解析WIF格式
	key, err := btcutil.DecodeWIF(wif)
	if err != nil {
		return "", err
	}
	// 计算公钥
	pubKey := key.PrivKey.PubKey()
	// 生成地址
	addrPk, err := btcutil.NewAddressPubKey(pubKey.SerializeUncompressed(), &param)
	if err != nil {
		return "", err
	}
	// 输出地址
	addr := addrPk.EncodeAddress()
	return addr, nil
}

// GetAddressByPrivateKey 根据PrivateKey获取对应的地址
func GetAddressByPrivateKey(key *PrivateKey, netType string) (string, error) {
	prikWIF, err := Key2WIF(key.Key, netType)
	if err != nil {
		return "", err
	}
	address, err := GetAddressByWIF(prikWIF, netType)
	if err != nil {
		return "", err
	}
	return address, nil
}

// GetAddressByPrivateKey 根据PrivateKey获取对应的地址
func GetAddressByKey(key *[]byte, netType string) (string, error) {
	prikWIF, err := Key2WIF(*key, netType)
	if err != nil {
		return "", err
	}
	address, err := GetAddressByWIF(prikWIF, netType)
	if err != nil {
		return "", err
	}
	return address, nil
}

// GetAddressByPubKey 根据PublicKey获取对应的地址
func GetAddressByPubKey(key *PublicKey, netType string) (string, error) {
	var param chaincfg.Params
	switch netType {
	case "simnet":
		param = chaincfg.SimNetParams
	case "testnet":
		param = chaincfg.TestNet3Params
	case "mainnet":
		param = chaincfg.MainNetParams
	default:
		return "", errors.New("error netType")
	}
	// 生成地址
	pubKey, err := secp256k1.ParsePubKey(key.Key)
	if err != nil {
		return "", err
	}
	addr, err := btcutil.NewAddressPubKey(pubKey.SerializeUncompressed(), &param)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

// Key2WIF 将私钥转换为 WIF 格式
func Key2WIF(privateKey []byte, netType string) (string, error) {
	// 选择网络字节
	var networkByte byte
	switch netType {
	case "mainnet":
		networkByte = 0x80 // 主网
	case "testnet":
		networkByte = 0xEF // 测试网
	case "simnet":
		networkByte = 0x64 //模拟网
	default:
		return "", errors.New("netType error")
	}
	// 创建新的字节数组，长度为私钥长度 + 1 + 4（校验和）
	wif := make([]byte, 0, len(privateKey)+1+4)
	wif = append(wif, networkByte)   // 添加网络字节
	wif = append(wif, privateKey...) // 添加私钥
	// 计算校验和
	checksum := sha256.Sum256(wif)        // 第一次SHA-256
	checksum = sha256.Sum256(checksum[:]) // 第二次SHA-256
	checksum2 := checksum[:4]             // 取前4字节作为校验和
	// 将校验和添加到WIF末尾
	wif = append(wif, checksum2...)
	// 进行Base58编码
	return base58.Encode(wif), nil
}
