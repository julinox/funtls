package handshake

type xChangeCipherSpec struct {
}

func NewChangeCipherSpec() ChangeCipherSpec {
	return &xChangeCipherSpec{}
}

func (x *xChangeCipherSpec) Name() string {
	return "_ChangeCipherSpec_"
}

func (x *xChangeCipherSpec) Next() (int, error) {
	return 0, nil
}

func (x *xChangeCipherSpec) Handle(data []byte) error {
	return nil
}
