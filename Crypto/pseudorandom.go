// Package Crypto
package Crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/rand"
	"strings"
	"time"
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

// 生成指定长度的随机字符串
func GenerateRandomContent(length int) string {
	// 初始化随机种子
	rand.Seed(time.Now().UnixNano())

	// 字母数字字符集
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// 使用 strings.Builder 高效拼接字符串
	var builder strings.Builder
	builder.Grow(length)
	for i := 0; i < length; i++ {
		randomChar := charset[rand.Intn(len(charset))]
		builder.WriteByte(randomChar)
	}
	// 获取最终字符串
	randomString := builder.String()
	return randomString
}
