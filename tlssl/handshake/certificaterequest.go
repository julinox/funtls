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
	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xCertificateRequest) Handle(data []byte) error {
	fmt.Println("I AM: ", x.Name())
	return nil
}
