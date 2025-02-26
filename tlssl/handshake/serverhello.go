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
	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xServerHello) Handle(data []byte) error {
	fmt.Println("I AM: ", x.Name())
	x.nextState = CERTIFICATE
	return nil
}
