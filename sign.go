package cfcasm2go

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"

	"github.com/tjfoc/gmsm/sm2"
)

// defaultUID 默认UID
var defaultUID = []byte("1234567812345678")

// SM2Sign SM2私钥加签，返回Base64格式编码
//
// priKey SM2 私钥
//
// data   需要加密的数据
//
// uid    UID
func SM2Sign(priKey *sm2.PrivateKey, data, uid []byte) (string, error) {
	if bytes.Equal(uid, nil) {
		uid = defaultUID
	}
	r, s, err := sm2.Sm2Sign(priKey, data, uid, rand.Reader)
	if err != nil {
		return "", err
	}
	der := DerEncode(*r, *s)
	return base64.StdEncoding.EncodeToString(der), nil
}

// SM2Verify SM2公钥验签
//
// pubKey SM2公钥
//
// data 原始数据
//
// uid UID
//
// sign 签名串
func SM2Verify(pubKey *sm2.PublicKey, data, uid, sign []byte) bool {
	if bytes.Equal(uid, nil) {
		uid = defaultUID
	}

	rs := DerDecode(sign)
	return sm2.Sm2Verify(pubKey, data, uid, rs[0], rs[1])
}
