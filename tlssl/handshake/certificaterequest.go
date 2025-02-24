package handshake

type xCertificateRequest struct {
}

func NewCertificateRequest() CertificateRequest {
	return &xCertificateRequest{}
}

func (x *xCertificateRequest) Name() string {
	return "_CertificateRequest_"
}

func (x *xCertificateRequest) Next() (int, error) {
	return 0, nil
}

func (x *xCertificateRequest) Handle(data []byte) error {
	return nil
}
