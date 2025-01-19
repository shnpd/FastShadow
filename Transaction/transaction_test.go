package Transaction

import (
	"covertCommunication/RPC"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"testing"
)

func TestFilterTransByInputaddr(t *testing.T) {
	client := RPC.InitClient("localhost:28334", "mainnet")
	addr := "1J9uWa9asgXyodYdtcPoRLe4a82RvHq8j7"
	address, err := btcutil.DecodeAddress(addr, &chaincfg.MainNetParams)
	if err != nil {
		t.Error(err)
	}
	FilterTransByInputaddr(client, address)
}
