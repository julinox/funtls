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

func TestTLSCipherTextDecode(t *testing.T) {
	lg := testLogger()
	spec := cipherSpec()
	if spec == nil {
		lg.Info("nil cipher spec")
		return
	}

	// Suite is AES_256_CBC_SHA256 (0x003D)
	ct := cipherText()
	tct, err := spec.Decode(ct)
	if err != nil {
		lg.Error(err)
	}

	lg.Infof("Content: %x", tct.Fragment.(*tlssl.GenericBlockCipher).Content)
}

func testLogger() *logrus.Logger {
	lg := clog.InitNewLogger(&clog.CustomFormatter{Tag: "TESTER"})
	lg.SetLevel(logrus.DebugLevel)
	return lg
}

func cipherSuite() suite.Suite {
	return ciphersuites.NewAES_256_CBC_SHA256()
}

func keys() *tlssl.Keys {

	key, _ := hex.DecodeString("b95ec862429f25237f074a090d3e13b2027a58c200e7f74eee95b0d221f87f99")
	mac, _ := hex.DecodeString("b59b5590829a6513a5ac10da10aef8201d16c8f05ecc6fe517cf5d8024cad207")
	iv, _ := hex.DecodeString("a18028ef92695cbeac6259248d93f81f")

	return &tlssl.Keys{
		MAC: mac,
		Key: key,
		IV:  iv,
	}
}

func cipherSpec() tlssl.TLSCipherSpec {
	return tlssl.NewTLSCipherSpec(cipherSuite(), keys(), tlssl.MODE_MTE)
}

func cipherText() []byte {

	// VerifyData: d852d8aaf6be5ce5383678a4
	message := "160303005005c49737a3d2ec3927ddc423f427d6ae23044a30e5eb8e97d34e268f921c7dd551f9f19c24bf08711073049c03c45b7e85840f3cec3f065eabd31085496d9806081dde85ff583dd7b1cd5034bb2ee721"
	ct, _ := hex.DecodeString(message)
	return ct
}
