package handshake

import (
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type HandShake struct {
	CliHelo    CliHello
	ServerHelo ServerHello
}

func InitHandhsake(lg *logrus.Logger, mods mx.TLSModulo) (*HandShake, error) {

	var newHsIf HandShake

	//newHsIf.CliHelo = NewCliHello(lg)
	return &newHsIf, nil
}
