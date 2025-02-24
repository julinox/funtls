package handshake

type xCertificate struct {
}

func NewCertificate() Certificate {
	return &xCertificate{}
}

func (x *xCertificate) Name() string {
	return "_Certificate_"
}

func (x *xCertificate) Next() (int, error) {
	return 0, nil
}

func (x *xCertificate) Handle(data []byte) error {
	return nil
}
