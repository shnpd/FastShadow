package fileoperator

import (
	"fmt"
	"github.com/xuri/excelize/v2"
	"os"
)

// SaveSignature 将签名数组追加到 Excel 文件
func SaveSignature(signatures []string, savePath string) bool {
	var f *excelize.File
	var err error
	sheetName := "Sheet1"

	// 检查文件是否存在
	if _, err := os.Stat(savePath); err == nil {
		// 文件存在，打开文件
		f, err = excelize.OpenFile(savePath)
		if err != nil {
			fmt.Println("无法打开文件:", err)
			return false
		}
	} else {
		// 文件不存在，创建新文件
		f = excelize.NewFile()
		f.NewSheet(sheetName)
	}

	// 获取现有的行数，找到最后一行
	rows, err := f.GetRows(sheetName)
	if err != nil {
		fmt.Println("无法读取行:", err)
		return false
	}
	startRow := len(rows) + 1 // 新数据开始的行号

	// 将字符串数组追加到 Excel 文件
	for i, value := range signatures {
		cell := fmt.Sprintf("A%d", startRow+i) // A列，目标行号
		f.SetCellValue(sheetName, cell, value)
	}

	// 保存文件
	if err := f.SaveAs(savePath); err != nil {
		fmt.Println("无法保存文件:", err)
		return false
	}
	fmt.Println("文件保存成功!")
	return true
}
