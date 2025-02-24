package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type xChangeCipherSpec struct {
}

func NewChangeCipherSpec() evilmac.State {
	return &xChangeCipherSpec{}
}

func (x *xChangeCipherSpec) Name() string {
	return "_Certificate_"
}

func (x *xChangeCipherSpec) Next() (int, error) {
	return 0, nil
}
