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

	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xChangeCipherSpec) Handle(data []byte) error {
	fmt.Println("I AM: ", x.Name())
	return nil
}
