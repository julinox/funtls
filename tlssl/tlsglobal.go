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
	OptClientAuth bool
	CertPKI       pki.CertPKI
	Lg            *logrus.Logger
	TLSSuite      mx.ModTLSSuite
	Exts          *ex.Extensions
}
