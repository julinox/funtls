package handshake

import "fmt"

type xServerKeyExchange struct {
	stateBasicInfo
}

func NewServerKeyExchange(ctx HandShakeContext) ServerKeyExchange {

	var newX xServerKeyExchange

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xServerKeyExchange) Name() string {
	return "_ServerKeyExchange_"
}

func (x *xServerKeyExchange) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xServerKeyExchange) Handle() error {

	if x.ctx.GetOptClientAuth() {
		x.nextState = CERTIFICATEREQUEST
	} else {
		x.nextState = SERVERHELLODONE
	}

	fmt.Println("I AM: ", x.Name())
	return nil
}
