package handshake

import "fmt"

type xServerHello struct {
	stateBasicInfo
}

func NewServerHello(ctx HandShakeContext) ServerHello {

	var newX xServerHello

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xServerHello) Name() string {
	return "_ServerHello_"
}

func (x *xServerHello) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xServerHello) Handle() error {

	x.nextState = CERTIFICATE
	fmt.Println("I AM: ", x.Name())
	return nil
}
