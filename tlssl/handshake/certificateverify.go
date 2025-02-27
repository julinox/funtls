package handshake

import "fmt"

type xCertificateVerify struct {
	stateBasicInfo
}

func NewCertificateVerify(ctx HandShakeContext) CertificateVerify {

	var newX xCertificateVerify

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xCertificateVerify) Name() string {
	return "_CertificateVerify_"
}

func (x *xCertificateVerify) Next() (int, error) {

	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xCertificateVerify) Handle(data []byte) error {

	fmt.Println("I AM: ", x.Name())
	return nil
}
