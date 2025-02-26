package handshake

import "fmt"

type xCertificate struct {
	stateBasicInfo
}

func NewCertificate(ctx HandShakeContext) Certificate {

	var newX xCertificate

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xCertificate) Name() string {
	return "_Certificate_"
}

func (x *xCertificate) Next() (int, error) {
	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xCertificate) Handle(data []byte) error {
	fmt.Println("I AM: ", x.Name())
	if x.ctx.GetOptClientAuth() {
		fmt.Println("MUTUAL AUTH ENABLE")
	}

	//fmt.Println("MUTUAL AUTH ->". x.)
	return nil
}
