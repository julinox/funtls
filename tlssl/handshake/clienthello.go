package handshake

type xClientHello struct {
	nextState int
	nextError error
}

func NewClientHello() ClientHello {
	return &xClientHello{}
}

func (x *xClientHello) Name() string {
	return "_ClientHello_"
}

func (x *xClientHello) Next() (int, error) {
	return x.nextState, x.nextError
}

func (x *xClientHello) Handle(data []byte) error {
	return nil
}
