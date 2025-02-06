package interfaces

import (
	"tlesio/systema"
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type IfaceParams struct {
	Lg *logrus.Logger
	Mx *mx.ModuloZ
	Ex *ex.Extensions
}

type Interfaces struct {
	TLSHead     Header
	CliHelo     CliHello
	ServerHelo  ServerHello
	Certificake Certificate
}

func InitInterfaces(params *IfaceParams) (*Interfaces, error) {

	var newHsIf Interfaces

	if params == nil || params.Lg == nil ||
		params.Mx == nil || params.Ex == nil {
		return nil, systema.ErrNilParams
	}

	newHsIf.TLSHead = NewHeader()
	params.Lg.Info("Interface loaded: ", newHsIf.TLSHead.Name())
	newHsIf.CliHelo = NewIfCliHello(params)
	params.Lg.Info("Interface loaded: ", newHsIf.CliHelo.Name())
	newHsIf.ServerHelo = NewIfcServerHello(params)
	params.Lg.Info("Interface loaded: ", newHsIf.ServerHelo.Name())
	newHsIf.Certificake = NewIfcCertificate(params.Lg)
	params.Lg.Info("Interface loaded: ", newHsIf.Certificake.Name())
	return &newHsIf, nil
}
