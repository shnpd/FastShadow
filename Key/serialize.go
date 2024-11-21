package Key

import (
	"bytes"
	"covertCommunication/Crypto"
	"encoding/binary"
	"math/big"
)

// 将32位无符号整数i序列化为4字节序列，最高有效字节优先
func serializeUint32(i uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, i)
	return buf
}

// 将坐标对P = (x,y)序列化为字节序列，使用SEC1的压缩形式:(0x02或0x03) || ser256(x)，其中头字节取决于省略的y坐标的奇偶校验。
func serializePub(x *big.Int, y *big.Int) []byte {
	var key bytes.Buffer

	// Write header; 0x2 for even y value; 0x3 for odd
	err := key.WriteByte(byte(0x2) + byte(y.Bit(0)))
	if err != nil {
		return nil
	}

	// Write X coord; Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
	xBytes := x.Bytes()
	for i := 0; i < (33 - 1 - len(xBytes)); i++ {
		err := key.WriteByte(0x0)
		if err != nil {
			return nil
		}
	}
	_, err = key.Write(xBytes)
	if err != nil {
		return nil
	}
	return key.Bytes()
}

// 将序列化公钥扩展为坐标对形式
func deserializePub(key []byte) (*big.Int, *big.Int) {
	params := curveParams
	exp := big.NewInt(1)
	exp.Add(params.P, exp)
	exp.Div(exp, big.NewInt(4))
	x := big.NewInt(0).SetBytes(key[1:33])
	y := big.NewInt(0).SetBytes(key[:1])
	beta := big.NewInt(0)
	// #nosec
	beta.Exp(x, big.NewInt(3), nil)
	beta.Add(beta, big.NewInt(7))
	// #nosec
	beta.Exp(beta, exp, params.P)
	if y.Add(beta, y).Mod(y, big.NewInt(2)).Int64() == 0 {
		y = beta
	} else {
		y = beta.Sub(params.P, beta)
	}
	return x, y
}

//
//// SerializePub 序列化公钥
//func (key *PublicKey) SerializePub() []byte {
//	// Private keys should be prepended with a single null byte
//	keyBytes := key.Key
//	// Write fields to buffer in order
//	buffer := new(bytes.Buffer)
//	_, err := buffer.Write(key.Version)
//	if err != nil {
//		return nil
//	}
//	err = buffer.WriteByte(key.Depth)
//	if err != nil {
//		return nil
//	}
//	_, err = buffer.Write(key.FatherFinger)
//	if err != nil {
//		return nil
//	}
//	_, err = buffer.Write(key.ChildNumber)
//	if err != nil {
//		return nil
//	}
//	_, err = buffer.Write(key.Chaincode)
//	if err != nil {
//		return nil
//	}
//	_, err = buffer.Write(keyBytes)
//	if err != nil {
//		return nil
//	}
//	// Append the standard doublesha256 checksum
//	serializedKey := addChecksumToBytes(buffer.Bytes())
//	return serializedKey
//}

func addChecksumToBytes(data []byte) []byte {
	checksum := checksum(data)
	return append(data, checksum...)
}
func checksum(data []byte) []byte {
	return Crypto.HashDoubleSha256(data)[:4]
}
