package handshake

import (
	syst "tlesio/systema"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type HandShake struct {
	CliHelo    CliHello
	ServerHelo ServerHello
}

func InitHandhsakeIf(lg *logrus.Logger, mods mx.TLSModulo) (*HandShake, error) {

	var newHsIf HandShake

	newHsIf.CliHelo = NewCliHello(lg, mods)
	if newHsIf.CliHelo == nil {
		return nil, syst.ErrNilModulo
	}

	lg.Info("Interface loaded: ", newHsIf.CliHelo.Name())
	newHsIf.ServerHelo = NewServerHello(lg, mods)
	if newHsIf.ServerHelo == nil {
		return nil, syst.ErrNilModulo
	}

	lg.Info("Interface loaded: ", newHsIf.ServerHelo.Name())
	return &newHsIf, nil
}
