package cfcasm2go

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

// GenSM2PrivateKey 根据提供的公钥十六进制编码X Y, 私钥十六进制编码D，生成SM2私钥
//
// hexD 私钥D的十六进制编码
//
// hexX 公钥X的十六进制编码
//
// hexY 公钥Y的十六进制编码
func GenSM2PrivateKey(hexD, hexX, hexY string) (sm2.PrivateKey, error) {
	priKey := sm2.PrivateKey{}

	priD, err := hex.DecodeString(hexD)
	if err != nil {
		return priKey, fmt.Errorf("私钥D十六进制解码失败：%s", err)
	}
	priKey.D = new(big.Int).SetBytes(priD)

	pubKey, err := GenSM2PublicKey(hexX, hexY)
	if err != nil {
		return priKey, err
	}
	priKey.PublicKey = pubKey
	return priKey, nil
}

// GenSM2PublicKey 根据提供的公钥十六进制编码X|Y生成SM2公钥
//
// hexX 公钥X的十六进制编码
//
// hexY 公钥Y的十六进制编码
func GenSM2PublicKey(hexX, hexY string) (sm2.PublicKey, error) {
	pubKey := sm2.PublicKey{}

	x, err := hex.DecodeString(hexX)
	if err != nil {
		return pubKey, fmt.Errorf("公钥生成失败, X十六进制解码失败：%s", err.Error())
	}
	pubKey.X = new(big.Int).SetBytes(x)

	y, err := hex.DecodeString(hexY)
	if err != nil {
		return pubKey, fmt.Errorf("公钥生成失败, Y十六进制解码失败：%s", err.Error())
	}
	pubKey.Y = new(big.Int).SetBytes(y)

	pubKey.Curve = sm2.P256Sm2()
	return pubKey, nil
}
