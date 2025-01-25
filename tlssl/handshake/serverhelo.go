package handshake

import (
	tx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type ServerHello interface {
	Handle(*MsgHello) error
}

type xServerHello struct {
	lg     *logrus.Logger
	modsIf tx.TLSModulo
}

func NewServerHello(lg *logrus.Logger, mods tx.TLSModulo) ServerHello {

	if lg == nil || mods == nil {
		return nil
	}

	return &xServerHello{
		lg:     lg,
		modsIf: mods,
	}
}

func (sh *xServerHello) Handle(msg *MsgHello) error {

	if msg == nil {
		return nil
	}

	sh.lg.Info("ServerHello message received")
	return nil
}
