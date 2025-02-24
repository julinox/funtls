package handshake

type xServerKeyExchange struct {
}

func NewServerKeyExchange() ServerKeyExchange {
	return &xServerKeyExchange{}
}

func (x *xServerKeyExchange) Name() string {
	return "_ServerKeyExchange_"
}

func (x *xServerKeyExchange) Next() (int, error) {
	return 0, nil
}

func (x *xServerKeyExchange) Handle([]byte) error {
	return nil
}
