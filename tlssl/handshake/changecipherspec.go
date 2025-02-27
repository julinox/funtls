package handshake

import "fmt"

type xChangeCipherSpec struct {
	stateBasicInfo
}

func NewChangeCipherSpec(ctx HandShakeContext) ChangeCipherSpec {

	var newX xChangeCipherSpec

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xChangeCipherSpec) Name() string {
	return "_ChangeCipherSpec_"
}

func (x *xChangeCipherSpec) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xChangeCipherSpec) Handle() error {

	x.nextState = FINISHED
	fmt.Println("I AM: ", x.Name())
	return nil
}
