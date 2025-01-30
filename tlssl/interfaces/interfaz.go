package interfaces

import (
	syst "tlesio/systema"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type Interfaces struct {
	TLSHead    Header
	CliHelo    CliHello
	ServerHelo ServerHello
}

func InitInterfaces(lg *logrus.Logger, mods mx.TLSModulo) (*Interfaces, error) {

	var newHsIf Interfaces

	newHsIf.TLSHead = NewHeader()
	lg.Info("Interface loaded: ", newHsIf.TLSHead.Name())
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
