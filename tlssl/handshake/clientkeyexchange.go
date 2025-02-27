package handshake

import "fmt"

type xClientKeyExchange struct {
	stateBasicInfo
}

func NewClientKeyExchange(ctx HandShakeContext) ClientKeyExchange {

	var newX xClientKeyExchange

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xClientKeyExchange) Name() string {
	return "_ClientKeyExchange_"
}

func (x *xClientKeyExchange) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xClientKeyExchange) Handle() error {

	if x.ctx.GetOptClientAuth() {
		x.nextState = CERTIFICATEVERIFY
	} else {
		x.nextState = CHANGECIPHERSPEC
	}

	fmt.Println("I AM: ", x.Name())
	return nil
}
