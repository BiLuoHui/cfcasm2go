package cfcasm2go

import (
	"math/big"
)

// DerEncode DER编码
//
// M2签名值的DER编码格式: 0x30 + 数据总长度 + 0x02 + R的长度 + R + 0x02 + S的长度 + S
func DerEncode(R, S big.Int) []byte {
	r := R.Bytes()
	s := S.Bytes()
	rLen := len(r)
	sLen := len(s)

	der := make([]byte, 6+rLen+sLen)
	der[0] = 0x30
	der[1] = byte(4 + rLen + sLen)
	der[2] = 0x20
	der[3] = byte(rLen)
	copy(der[4:4+rLen], r)
	der[4+rLen] = 0x02
	der[5+rLen] = byte(sLen)
	copy(der[6+rLen:], s)
	return der
}

// DerDecode DER解码
func DerDecode(der []byte) [2]*big.Int {
	rLen := der[3]
	r := make([]byte, rLen)
	copy(r, der[4:4+rLen])

	sLen := der[5+rLen]
	s := make([]byte, sLen)
	copy(s, der[6+rLen:])

	rs := [2]*big.Int{}
	rs[0] = new(big.Int).SetBytes(r)
	rs[1] = new(big.Int).SetBytes(s)

	return rs
}
