package handshake

import "fmt"

type xCertificateRequest struct {
	stateBasicInfo
}

func NewCertificateRequest(ctx HandShakeContext) CertificateRequest {

	var newX xCertificateRequest

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xCertificateRequest) Name() string {
	return "_CertificateRequest_"
}

func (x *xCertificateRequest) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xCertificateRequest) Handle() error {

	x.nextState = SERVERHELLODONE
	fmt.Println("I AM: ", x.Name())
	return nil
}
