package handshake

type xClientKeyExchange struct {
}

func NewClientKeyExchange() ClientKeyExchange {
	return &xClientKeyExchange{}
}

func (x *xClientKeyExchange) Name() string {
	return "_ClientKeyExchange_"
}

func (x *xClientKeyExchange) Next() (int, error) {
	return 0, nil
}

func (x *xClientKeyExchange) Handle(data []byte) error {
	return nil
}
