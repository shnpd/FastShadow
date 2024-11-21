package Crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
	"io"
)

func HashSHA256(data []byte) []byte {
	newHash := sha256.New()
	_, err := newHash.Write(data)
	if err != nil {
		return nil
	}
	return newHash.Sum(nil)
}

func HashSha256(data []byte) []byte {
	newHash := sha256.New()
	_, err := newHash.Write(data)
	if err != nil {
		return nil
	}
	return newHash.Sum(nil)
}

func HashDoubleSha256(data []byte) []byte {
	return HashSha256(HashSha256(data))
}

func HashRipeMD160(data []byte) []byte {
	newHash := ripemd160.New()
	_, err := io.WriteString(newHash, string(data))
	if err != nil {
		return nil
	}
	return newHash.Sum(nil)
}
func Hash160(data []byte) []byte {
	return HashRipeMD160(HashSha256(data))
}

func NewSeed() ([]byte, error) {
	// Well that easy, just make go read 256 random bytes into a slice
	s := make([]byte, 256)
	_, err := rand.Read(s)
	return s, err
}
