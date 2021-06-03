package cfcasm2go

import (
	"encoding/base64"
	"log"
	"testing"
)

const (
	priD       = "7CD798AF4F6643E844591902569A4E35514A21E9866D537892115AC21494C550"                                 // 私钥
	pubX       = "021091496615CF1C69B631D393C68BECCAFCCEAC5527667E95328F8ABF5CF5A4"                                 // 公钥X
	pubY       = "03A2A7B640E67E861B336FC7589486257A7D841159D11696C3F4296E0F21A0D5"                                 // 公钥Y
	signature  = "MEUgIQCz+r8a1Qc52grbWe2TC843kREv+XJiaAj3qvtt0DMfmAIgSkTMIl7i0SbvMFO18bUE+Lnw35HRKv9yxTp6rWTxAyM=" // JAVA加签后数据
	sourceData = "userData"                                                                                         // 原始数据
)

func TestSM2Verify(t *testing.T) {
	pubKey, err := GenSM2PublicKey(pubX, pubY)
	if err != nil {
		t.Fatalf("公钥生成失败：%s\n", err)
	}
	sign, _ := base64.StdEncoding.DecodeString(signature)
	verify := SM2Verify(&pubKey, []byte(sourceData), defaultUID, sign)
	if !verify {
		t.Fatal("验签失败")
	}
}

func TestSM2Sign(t *testing.T) {
	priKey, err := GenSM2PrivateKey(priD, pubX, pubY)
	if err != nil {
		log.Fatalln(err)
	}

	sign, err := SM2Sign(&priKey, []byte(sourceData), defaultUID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(sign)
}
