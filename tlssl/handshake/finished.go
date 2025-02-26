package handshake

import "fmt"

type xFinished struct {
	stateBasicInfo
}

func NewFinished(ctx HandShakeContext) Finished {

	var newX xFinished

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xFinished) Name() string {
	return "_Finished_"
}

func (x *xFinished) Next() (int, error) {
	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xFinished) Handle(data []byte) error {
	fmt.Println("I AM: ", x.Name())
	return nil
}
