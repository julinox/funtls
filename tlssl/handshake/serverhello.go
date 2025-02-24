package handshake

type xServerHello struct {
}

func NewServerHello() ServerHello {
	return &xServerHello{}
}

func (x *xServerHello) Name() string {
	return "_ServerHello_"
}

func (x *xServerHello) Next() (int, error) {
	return 0, nil
}

func (x *xServerHello) Handle(data []byte) error {
	return nil
}
