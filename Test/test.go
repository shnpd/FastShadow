package test

import (
	"encoding/hex"
	"fmt"
)

type MyStruct struct {
	Value int
}

func (m MyStruct) Increment() {
	m.Value++
}

func main() {
	seed, err := hex.DecodeString("111oi")
	if err != nil {
		fmt.Println(1111)
	}
	fmt.Println(22222, seed)
}
