package Key

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

// ValidatePrivateKey 验证种子生成的主密钥是否合法
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

// ValidateDeprivPrivateKey 验证派生私钥是否合法
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
