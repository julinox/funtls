package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type xServerHelloDone struct {
}

func NewServerHelloDone() evilmac.State {
	return &xCertificate{}
}

func (x *xServerHelloDone) Name() string {
	return "_Certificate_"
}

func (x *xServerHelloDone) Next() (int, error) {
	return 0, nil
}
