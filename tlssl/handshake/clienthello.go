package handshake

import (
	"github.com/julinox/statemaquina"
)

type clientHello struct {
	buffer []byte
}

func (x *clientHello) Name() string {
	return "_ClientHello_"
}

func (x *clientHello) Next() (int, error) {
	return HANDSHAKE_SERVERHELLO, nil
}

func NewClientHello() statemaquina.State {

	return &clientHello{}
}
