package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type xServerKeyExchange struct {
}

func NewServerKeyExchange() evilmac.State {
	return &xCertificate{}
}

func (x *xServerKeyExchange) Name() string {
	return "_Certificate_"
}

func (x *xServerKeyExchange) Next() (int, error) {
	return 0, nil
}
