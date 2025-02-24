package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type xCertificate struct {
}

func NewCertificate() evilmac.State {
	return &xCertificate{}
}

func (x *xCertificate) Name() string {
	return "_Certificate_"
}

func (x *xCertificate) Next() (int, error) {
	return 0, nil
}
