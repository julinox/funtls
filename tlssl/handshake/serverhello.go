package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type xServerHello struct {
}

func NewServerHello() evilmac.State {
	return &xCertificate{}
}

func (x *xServerHello) Name() string {
	return "_Certificate_"
}

func (x *xServerHello) Next() (int, error) {
	return 0, nil
}
