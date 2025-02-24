package handshake

type xServerHelloDone struct {
}

func NewServerHelloDone() ServerHelloDone {
	return &xServerHelloDone{}
}

func (x *xServerHelloDone) Name() string {
	return "_ServerHelloDone_"
}

func (x *xServerHelloDone) Next() (int, error) {
	return 0, nil
}

func (x *xServerHelloDone) Handle(data []byte) error {
	return nil
}
