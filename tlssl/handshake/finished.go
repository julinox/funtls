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
	return x.nextState, x.Handle()
}

func (x *xFinished) Handle() error {

	fmt.Println("I AM: ", x.Name())
	return nil
}
