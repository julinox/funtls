package tlssl

import (
	ex "github.com/julinox/funtls/tlssl/extensions"
	mx "github.com/julinox/funtls/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type TLSContext struct {
	Lg *logrus.Logger
	//Modz          *mx.ModuloZ
	Certs         mx.ModCerts
	TLSSuite      mx.ModTLSSuite
	Exts          *ex.Extensions
	OptClientAuth bool // Enable Client Authentication
}
