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
	return x.nextState, x.Handle()
}

func (x *xCertificateVerify) Handle() error {

	fmt.Println("I AM: ", x.Name())
	return nil
}
