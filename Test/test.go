package main

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
	"github.com/xuri/excelize/v2"
	"log"
	"net/http"
	"os"
)

func main() {
	// 定义目标URL
	url := "https://api.3xpl.com/bitcoin/address/bc1p7m3rtqkvfvgenlgge7px584vk0xax82m80wskljpgg9d739jj8asv04fck?token=3A0_t3st3xplor3rpub11cb3t4efcd21748a5e&data=events"

	// 发送GET请求
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

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
