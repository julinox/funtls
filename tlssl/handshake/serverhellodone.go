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
	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xServerHelloDone) Handle(data []byte) error {
	fmt.Println("I AM: ", x.Name())
	return nil
}
