package tlssl

import (
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type TLSContext struct {
	Lg            *logrus.Logger
	Modz          *mx.ModuloZ
	Certs         mx.ModCerts
	TLSSuite      mx.ModTLSSuite
	Exts          *ex.Extensions
	OptClientAuth bool // Enable Client Authentication
}
