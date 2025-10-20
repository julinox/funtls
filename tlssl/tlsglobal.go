package tlssl

import (
	pki "github.com/julinox/funtls/tlssl/certpki"
	ex "github.com/julinox/funtls/tlssl/extensions"
	mx "github.com/julinox/funtls/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

const VERIFYDATALEN = 12

const (
	MODE_MTE = iota + 1
	MODE_ETM
)

type TLSContext struct {
	Lg            *logrus.Logger
	Certs         mx.ModCerts
	TLSSuite      mx.ModTLSSuite
	Exts          *ex.Extensions
	OptClientAuth bool // Enable Client Authentication
	CertPKI       pki.CertPKI
}
