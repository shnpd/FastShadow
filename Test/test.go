package main

import (
	"bytes"
	"covertCommunication/Crypto"
	"crypto/aes"
	"errors"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/xuri/excelize/v2"
	"log"
	"os"
)

func main() {
	covertMsg := "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	keyAES := []byte("1234567890123456")

	splitMsg := Split32bytes([]byte(covertMsg))

	// 加密每个分组
	var encryptMsg [][]byte
	for _, v := range splitMsg {
		cipher, err := Crypto.Encrypt(v, keyAES)
		fmt.Println(cipher)
		if err != nil {
			log.Fatal(err)
		}
		encryptMsg = append(encryptMsg, cipher)
	}
	k := new(secp256k1.ModNScalar)
	msg := string(encryptMsg[0])
	k_str_byte := []byte(msg)
	k.SetByteSlice(k_str_byte)
	fmt.Println(k_str_byte)
	fmt.Println(k.String())

	//plain, _ := Crypto.Decrypt(encryptMsg[0], keyAES)
	//fmt.Println(string(plain))
}

// Split32bytes 将字符串每32字节划分
func Split32bytes(msg []byte) [][]byte {
	chunkSize := 32
	var chunks [][]byte

	for i := 0; i < len(msg); i += chunkSize {
		end := i + chunkSize
		if end > len(msg) {
			end = len(msg)
		}
		chunks = append(chunks, msg[i:end])
	}
	return chunks
}

// PKCS7Padding 添加填充
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7Unpadding 移除填充
func PKCS7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("data is empty")
	}
	padding := int(data[length-1])
	return data[:(length - padding)], nil
}

// EncryptAES256 使用AES-256的ECB模式加密
func EncryptAES256(input []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 对输入数据进行填充，使其长度为AES块大小的倍数
	paddedInput := PKCS7Padding(input, block.BlockSize())
	encrypted := make([]byte, len(paddedInput))

	// ECB模式分块加密
	for start := 0; start < len(paddedInput); start += block.BlockSize() {
		end := start + block.BlockSize()
		block.Encrypt(encrypted[start:end], paddedInput[start:end])
	}

	return encrypted, nil
}

// DecryptAES256 使用AES-256的ECB模式解密
func DecryptAES256(encrypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encrypted))

	// ECB模式分块解密
	for start := 0; start < len(encrypted); start += block.BlockSize() {
		end := start + block.BlockSize()
		block.Decrypt(decrypted[start:end], encrypted[start:end])
	}

	// 移除填充
	return PKCS7Unpadding(decrypted)
}

func newFile() {
	f := excelize.NewFile()

	f.NewSheet("Sheet1")

	// 保存文件
	if err := f.SaveAs("DataAnalysis/DataSet/CovertSig.xlsx"); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("File created successfully.")
	}
}

// SaveSignature 将签名数组保存到excel文件
func AppendSignature(signatures, savePath string) error {
	var f *excelize.File
	// 打开Excel文件
	if _, err := os.Stat(savePath); os.IsNotExist(err) {
		// 如果文件不存在，则创建一个新的 .xlsx 文件
		f = excelize.NewFile()
		// 保存文件
		if err := f.SaveAs(savePath); err != nil {
			return fmt.Errorf("failed to create xlsx file: %w", err)
		}
	} else {
		// 如果文件存在，打开文件
		f, err = excelize.OpenFile(savePath)
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
	}
	defer f.Close()
	return nil
}
