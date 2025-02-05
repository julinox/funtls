package interfaces

import (
	"tlesio/systema"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type Interfaces struct {
	TLSHead     Header
	CliHelo     CliHello
	ServerHelo  ServerHello
	Certificake Certificate
}

func InitInterfaces(lg *logrus.Logger, mods *mx.ModuloZ) (*Interfaces, error) {

	var newHsIf Interfaces

	if lg == nil || mods == nil {
		return nil, systema.ErrNilParams
	}

	newHsIf.TLSHead = NewHeader()
	lg.Info("Interface loaded: ", newHsIf.TLSHead.Name())
	newHsIf.CliHelo = NewIfCliHello(lg, mods)
	lg.Info("Interface loaded: ", newHsIf.CliHelo.Name())
	newHsIf.ServerHelo = NewIfcServerHello(lg, mods)
	lg.Info("Interface loaded: ", newHsIf.ServerHelo.Name())
	newHsIf.Certificake = NewIfcCertificate(lg)
	lg.Info("Interface loaded: ", newHsIf.Certificake.Name())
	return &newHsIf, nil
}
