package cipherspec

import (
	"encoding/hex"
	"testing"

	"tlesio/tlssl"
	"tlesio/tlssl/suite"
	"tlesio/tlssl/suite/ciphersuites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

func TestEameEste(t *testing.T) {
	lg := testLogger()
	spec := cipherSpec()
	if spec == nil {
		lg.Info("nil cipher spec")
		return
	}

	ct := cipherText()
	_, err := spec.Decode(ct)
	if err != nil {
		lg.Error(err)
	}
}

func testLogger() *logrus.Logger {
	lg := clog.InitNewLogger(&clog.CustomFormatter{Tag: "TESTER"})
	lg.SetLevel(logrus.DebugLevel)
	return lg
}

func traje() suite.Suite {
	return ciphersuites.NewAES_256_CBC_SHA256()
}

func keys() *tlssl.Keys {

	key, _ := hex.DecodeString("067d3b3db13874dcd6bf1a6019ca32c0e99a205c60f9dca021db75199b3602c6")
	mac, _ := hex.DecodeString("067d3b3db13874dcd6bf1a6019ca32c0e99a205c60f9dca021db75199b3602c6")
	iv, _ := hex.DecodeString("9b70dafc614106000ee77947193f3cd2")

	return &tlssl.Keys{
		MAC: mac,
		Key: key,
		IV:  iv,
	}
}

func cipherSpec() tlssl.TLSCipherSpec {
	return tlssl.NewTLSCipherSpec(traje(), keys(), suite.MTE)
}

func cipherText() []byte {

	cipherText := "842e530316f7f3fd52d0a7fc221ef4c0f88936be8c3e20ad821ca5e746da4f1ec6caf2dbec9792354cd66af48879338758edeca38cfd02fb8e37c3e8a6cdc25e59ea64df4f8d36fc36faf853b782732a"
	ct, _ := hex.DecodeString(cipherText)
	return ct
}
