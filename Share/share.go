package Share

import "github.com/btcsuite/btcd/chaincfg/chainhash"

var (
	IsTxSignOver = make(map[chainhash.Hash]bool) //交易的签名s是否超过一半
)
