package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type xClientKeyExchange struct {
}

func NewClientKeyExchange() evilmac.State {
	return &xCertificate{}
}

func (x *xClientKeyExchange) Name() string {
	return "_Certificate_"
}

func (x *xClientKeyExchange) Next() (int, error) {
	return 0, nil
}
