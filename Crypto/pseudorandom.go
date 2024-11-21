// Package Crypto
package Crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

func PRF(data []byte, key []byte) []byte {
	hmac := hmac.New(sha256.New, key)
	hmac.Write([]byte(data))
	ret := hmac.Sum(nil)
	return ret
}

func PRP(data []byte, key []byte) []byte {
	ret, _ := Encrypt(key, data)
	return ret
}
