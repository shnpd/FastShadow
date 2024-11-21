package main

import (
	"covertCommunication/KeyDerivation"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/xuri/excelize/v2"
	"log"
	"os"
	"strconv"
)

// init 生成根密钥对
func init() {
	InitSeed = []byte("initseed")
	Skroot, _ = KeyDerivation.GenerateMasterKey(InitSeed)
	Pkroot = KeyDerivation.EntirePublicKeyForPrivateKey(Skroot)
	BankRoot, _ = KeyDerivation.GenerateMasterKey([]byte("bank"))
	Kleak = "leak Random"
}

// 初始化钱包
func InitWallet() *rpcclient.Client {
	// 设置RPC客户端连接的配置
	connCfg := &rpcclient.ConnConfig{
		Host:         "localhost:28335", // 替换为你的btcwallet的RPC地址
		User:         "simnet",          // 在btcwallet配置文件中定义的RPC用户名
		Pass:         "simnet",          // 在btcwallet配置文件中定义的RPC密码
		HTTPPostMode: true,              // 使用HTTP POST模式
		DisableTLS:   true,              // 禁用TLS
		Params:       "simnet",          // 连接到simnet网
	}

	// 创建新的RPC客户端
	Client, _ = rpcclient.New(connCfg, nil)
	err := Client.WalletPassphrase("ts0", 6000)
	if err != nil {
		fmt.Println(err)
	}
	return Client
}

// 在执行此函数前首先执行test_transfer函数，向第0组地址转入utxo以便进行交易
// 在执行本函数时会循环执行十次嵌入操作，每次循环包括 生成地址-划分消息-平衡银行地址-发送隐蔽交易-发送泄露交易-向下一组地址的主密钥转入utxo以便其发送泄露交易
// 记录每次操作的时间延迟（因为银行地址每次的交易数量都不同，计算时间时暂时忽略银行地址）
func main() {
	InitWallet()
	defer Client.Shutdown()
	Covertmsg += EndFlag
	saveFilePath := "DataAnalysis/My_covert.xlsx"

	for round := 1; round <= 500; round++ {
		err := GenerateNewCntPrivKeys(round-1, 12)
		if err != nil {
			return
		}
		//	计算嵌入消息的字节数以及需要的隐蔽交易数（每个交易可以嵌入32字节）
		// 添加结束标志

		byteCnt := len([]byte(Covertmsg))
		msgCnt := (byteCnt + 31) / 32
		// 字符串每32字节划分
		splitMsg := SplitStrBy32bytes(Covertmsg)
		if round == 1 {
			fmt.Println(msgCnt)
		}
		//生成msgCnt个私钥用来接收交易
		err = GenerateNewCntPrivKeys(round, msgCnt)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = UpdateMapUTXOFromAddr()
		if err != nil {
			fmt.Println(err)
			return
		}

		//使用银行地址集平衡发送地址集的UTXO数量
		err = TransferBank(round, msgCnt)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = UpdateMapUTXOFromAddr()
		if err != nil {
			fmt.Println(err)
			return
		}
		//start := time.Now()
		//	发送隐蔽交易
		var covertTxid []*chainhash.Hash
		covertTxid, err = SendCovertTransaction(round, msgCnt, splitMsg)
		//_, err = SendCovertTransaction(round, msgCnt, splitMsg)
		//duration := time.Since(start)

		if err != nil {
			fmt.Println(err)
			return
		}
		var signatures []string

		for _, v := range covertTxid {
			signatures = append(signatures, getSigFromTx(v))
		}
		SaveSignature(signatures, saveFilePath)

		//for _, v := range covertTxid {
		//	fmt.Printf("Covert transaction id: %s\n", v.String())
		//}

		// 发送泄露交易
		//leakTrans, err := sendLeakTrans(round)
		_, err = SendLeakTrans(round)
		if err != nil {
			fmt.Println(err)
			return
		}
		//fmt.Printf("leak transaction id: %s\n", leakTrans.String())
		transMsk(round)
		_, err = Client.Generate(1)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

}

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

// transMsk 为第主密钥发送utxo以便发出泄露交易
func transMsk(mskId int) {
	destAddr, _ := KeyDerivation.GetAddressByPrivKey(MskSet[mskId])
	utxo := UTXObyAddress[MiningAddr][1]
	sourceTxid := utxo.TxID
	rawTx := generateTransFromUTXO(sourceTxid, destAddr, utxo.Amount)
	signTx, err := signTrans(rawTx, nil)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	broadTrans(signTx)
}

// 广播交易
func broadTrans(signedTx *wire.MsgTx) string {
	txHash, err := Client.SendRawTransaction(signedTx, false)
	if err != nil {
		log.Fatalf("Error sending transaction: %v", err)
	}
	return txHash.String()
}

// 签名交易，嵌入秘密消息
func signTrans(rawTx *wire.MsgTx, embedMsg *string) (*wire.MsgTx, error) {
	signedTx, complete, err, _ := Client.SignRawTransaction(rawTx, embedMsg)
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}
	if !complete {
		log.Fatalf("Transaction signing incomplete")
	}
	return signedTx, nil
}

// 生成sourceAddr到destAddr的原始交易（将UTXO全部转给目标地址，没有交易费）
func generateTransFromUTXO(txid, destAddr string, amount float64) *wire.MsgTx {
	// 构造输入
	var inputs []btcjson.TransactionInput
	inputs = append(inputs, btcjson.TransactionInput{
		Txid: txid,
		Vout: 0,
	})
	//	构造输出
	outAddr, _ := btcutil.DecodeAddress(destAddr, &chaincfg.SimNetParams)
	outputs := map[btcutil.Address]btcutil.Amount{
		outAddr: btcutil.Amount((amount - 0.1) * 1e8),
	}
	//	创建交易
	rawTx, err := Client.CreateRawTransaction(inputs, outputs, nil)
	if err != nil {
		log.Fatalf("Error creating raw transaction: %v", err)
	}
	return rawTx
}

// TODO:生成银行地址作为接收地址
// SendLeakTrans 发送round轮的主密钥的泄露交易，返回泄露交易id
func SendLeakTrans(round int) (*chainhash.Hash, error) {
	mskId := round - 1
	sourceAddr, err := KeyDerivation.GetAddressByPrivKey(MskSet[mskId])
	if err != nil {
		return nil, err
	}
	rawTx, err := GenerateTrans(sourceAddr, "ShRsmfcjFsNnGks4SiXWH2LNEravJmdbYd")
	if err != nil {
		return nil, err
	}
	signedTx, err := SignTrans(rawTx, &Kleak)
	if err != nil {
		return nil, err
	}
	txid, err := BroadTrans(signedTx)
	if err != nil {
		return nil, err
	}
	return txid, nil
}

// TransferBank 第round轮通信需要msgCnt个UTXO，处理发送地址持有的UTXO，多退少补，第round轮通信的主密钥序号为round-1（从0开始计算）
func TransferBank(round, msgCnt int) error {
	mskId := round - 1
	utxoNum := len(PrikSet[mskId])

	//utxo有多余，生成银行地址，将多余的utxo转入
	if utxoNum > msgCnt {
		minus := utxoNum - msgCnt
		err := GenerateCntBankKeys(minus)
		if err != nil {
			return err
		}
		for i := 0; i < minus; i++ {
			// 创建转出交易
			sourceAddr := AddressSet[mskId][msgCnt+i]
			if len(UTXObyAddress[sourceAddr]) == 0 {
				continue
			}
			destAddr, err := KeyDerivation.GetAddressByPrivKey(BankPrikSet[len(BankPrikSet)-i-1])
			if err != nil {
				return err
			}
			rawTx, err := GenerateTrans(sourceAddr, destAddr)
			if err != nil {
				return err
			}
			// 签名交易，该交易不嵌入信息
			signedTx, err := SignTrans(rawTx, nil)
			if err != nil {
				return err
			}
			_, err = BroadTrans(signedTx)
			if err != nil {
				return err
			}
		}
	} else {
		//	utxo数量不足，生成通信地址，从银行地址集提取
		minus := msgCnt - utxoNum
		for i := 0; i < minus; i++ {
			// 提取银行地址(默认银行地址足够用)
			bankPrik := BankPrikSet[0]
			BankPrikSet = BankPrikSet[1:]
			sourceAddr, err := KeyDerivation.GetAddressByPrivKey(bankPrik)
			if err != nil {
				return err
			}
			// 为主密钥mskid追加地址接收银行utxo
			err = AddCntPrivKeys(mskId, 1)
			if err != nil {
				return err
			}
			destAddr := AddressSet[mskId][utxoNum+i]
			rawTx, err := GenerateTrans(sourceAddr, destAddr)
			if err != nil {
				return err
			}
			signedTx, err := SignTrans(rawTx, nil)
			if err != nil {
				return err
			}
			_, err = BroadTrans(signedTx)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// generateNewCntPrivKey 生成idx个主密钥，并派生cnt个密钥
func GenerateNewCntPrivKeys(idx, cnt int) error {
	// 生成主密钥
	msk, _ := Skroot.ChildPrivateKeyDeprive(uint32(idx))
	err := ImportPrivkey(msk)
	if err != nil {
		return err
	}
	MskSet[idx] = msk
	//mskSet = append(mskSet, msk)
	var prikSetTemp []*KeyDerivation.PrivateKey
	var addressTemp []string
	//基于主密钥派生cnt个密钥
	for i := 0; i < cnt; i++ {
		key, _ := msk.ChildPrivateKeyDeprive(uint32(i))
		err := ImportPrivkey(key)
		if err != nil {
			return err
		}
		//更新密钥集及地址集
		prikSetTemp = append(prikSetTemp, key)
		address, err := KeyDerivation.GetAddressByPrivKey(key)
		if err != nil {
			return err
		}
		addressTemp = append(addressTemp, address)
	}
	PrikSet[idx] = prikSetTemp
	AddressSet[idx] = addressTemp
	return nil
}

// 更新地址持有UTXO的映射
func UpdateMapUTXOFromAddr() error {
	UTXObyAddress = map[string][]btcjson.ListUnspentResult{}
	allUTXO, err := Client.ListUnspent()
	if err != nil {
		return err
	}
	for _, utxo := range allUTXO {
		UTXObyAddress[utxo.Address] = append(UTXObyAddress[utxo.Address], utxo)
	}
	return nil
}

// 发送隐蔽交易
func SendCovertTransaction(round, msgCnt int, splitMsg []string) ([]*chainhash.Hash, error) {

	mskId := round - 1
	var covertTxid []*chainhash.Hash
	//	构造addrcnt个隐蔽交易,每个交易只有1个输入1个输出
	for i := 0; i < msgCnt; i++ {
		// 创建交易
		rawTx, err := GenerateTrans(AddressSet[mskId][i], AddressSet[mskId+1][i])
		if err != nil {
			return nil, err
		}
		//	签名交易(嵌入消息)
		signedTx, err := SignTrans(rawTx, &splitMsg[i])
		if err != nil {
			return nil, err
		}
		//	广播交易
		txId, err := BroadTrans(signedTx)
		if err != nil {
			return nil, err
		}
		covertTxid = append(covertTxid, txId)
	}

	return covertTxid, nil
}
func getSigFromTx(txid *chainhash.Hash) string {
	rawtx, err := Client.GetRawTransaction(txid)
	if err != nil {
		log.Fatal(err)
	}
	sigScript := hex.EncodeToString(rawtx.MsgTx().TxIn[0].SignatureScript)
	sigScript = sigScript[2:]
	length := sigScript[2:4]
	lenSig, _ := strconv.ParseInt(length, 16, 10)
	sigScript = sigScript[0 : 4+lenSig*2]
	return sigScript
}

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
