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

	x.Handle()
	return x.nextState, x.nextError
}

func (x *xCertificate) Handle() error {

	dh := true
	if dh {
		x.nextState = SERVERKEYEXCHANGE

	} else if x.ctx.GetOptClientAuth() {
		x.nextState = CERTIFICATEREQUEST

	} else {
		x.nextState = SERVERHELLODONE

	}

	fmt.Println("I AM: ", x.Name())
	return nil
}
