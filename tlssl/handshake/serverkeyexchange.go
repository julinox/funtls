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
	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xServerKeyExchange) Handle([]byte) error {
	fmt.Println("I AM: ", x.Name())
	return nil
}
