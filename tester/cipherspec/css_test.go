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
	spec.Decode(ct)
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

	return &tlssl.Keys{
		MAC: []byte("MAC"),
		Key: []byte("KEY"),
		IV:  []byte("IV"),
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
