package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type clientHello struct {
}

func (x *clientHello) Name() string {
	return "_ClientHello_"
}

func (x *clientHello) Next() (int, error) {
	return 0, nil
}

func NewClientHello() evilmac.State {

	return &clientHello{}
}
