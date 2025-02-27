package handshake

import "fmt"

type xServerHelloDone struct {
	stateBasicInfo
}

func NewServerHelloDone(ctx HandShakeContext) ServerHelloDone {

	var newX xServerHelloDone

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xServerHelloDone) Name() string {
	return "_ServerHelloDone_"
}

func (x *xServerHelloDone) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xServerHelloDone) Handle() error {

	x.nextState = TRANSITION
	fmt.Println("I AM: ", x.Name())
	return nil
}
