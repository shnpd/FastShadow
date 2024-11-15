package DataAnalysis

import (
	"fmt"
	"github.com/xuri/excelize/v2"
	"os"
	"strconv"
)

// GetSignatureFromCell 从excel列提取出签名
func GetSignatureFromHex(sigscript string) (string, bool) {
	// 开头有长度表示，添加[2:]去除标识
	sigscript = sigscript[2:]
	if sigscript[0:2] != "30" {
		return "", false
	}
	length := sigscript[2:4]
	lenSig, _ := strconv.ParseInt(length, 16, 10)
	if 4+lenSig*2 > int64(len(sigscript)) {
		return "", false
	}
	return sigscript[0 : 4+lenSig*2], true
}

// AppendSignature 将签名追加到excel文件
func AppendSignature(signatures, savePath string) error {
	sheet := "Sheet1"
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

	// 获取第一列当前的最大行号
	rows, err := f.GetRows(sheet)
	if err != nil {
		return fmt.Errorf("failed to get rows: %w", err)
	}
	rowNum := len(rows) + 1

	// 构造单元格坐标
	cell := fmt.Sprintf("A%d", rowNum)

	// 在第一列追加新值
	if err := f.SetCellValue(sheet, cell, signatures); err != nil {
		return fmt.Errorf("failed to set cell value: %w", err)
	}

	// 保存文件
	if err := f.Save(); err != nil {
		return fmt.Errorf("failed to save file: %w", err)
	}
	return nil
}
