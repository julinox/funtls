package handshake

import (
	evilmac "github.com/julinox/statemaquina"
)

type xCertificateRequest struct {
}

func NewCertificateRequest() evilmac.State {
	return &xCertificateRequest{}
}

func (x *xCertificateRequest) Name() string {
	return "_CertificateRequest_"
}

func (x *xCertificateRequest) Next() (int, error) {
	return 0, nil
}
