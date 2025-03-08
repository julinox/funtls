package keymaker

import (
	"testing"
	"tlesio/tlssl/suite/suites"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

func TestKeyMake(t *testing.T) {

	st := suites.NewAES_256_CBC_SHA256(ogLoc())

	// AES-CBC
	// sha256 = 32 bytes
	// KeyLen = 32 bytes
	// IV aes = 16 bytes
	// SessionKeys = 2 * (32 + 32 + 16) = 160 bytes

	st.PRF(nil, nil, 0)
}

func ogLoc() *logrus.Logger {
	lg := clog.InitNewLogger(&clog.CustomFormatter{Tag: "KEYMAKETEST"})
	lg.SetLevel(logrus.DebugLevel)
	return lg
}
