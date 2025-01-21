package main

import (
	"covertCommunication/Key"
	"covertCommunication/Transaction"
	"fmt"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"log"
	"testing"
	"time"
)

func TestDecodeAddr(t *testing.T) {
	start := time.Now()
	mpkId := 0
	mpk, err := pkRoot.ChildPublicKeyDeprive(uint32(mpkId), netType)
	if err != nil {
		log.Fatal(err)
	}
	mpkAddress, err := Key.GetAddressByPubKey(mpk, netType)
	fmt.Println(mpkAddress)
	address, err := btcutil.DecodeAddress("16mDJ7EEBjWvyJNX9oyaFS9fMVDjHTJfLZ", &chaincfg.MainNetParams)
	if err != nil {
		log.Fatal(err)
	}
	leakTxId, err := Transaction.FilterTransByInputaddr(client, address)
	if err != nil {
		log.Fatal(err)
	}
	dur := time.Since(start)
	fmt.Println(dur)
	fmt.Println(leakTxId)
}
