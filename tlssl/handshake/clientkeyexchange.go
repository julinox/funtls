package handshake

type xClientKeyExchange struct {
	stateBasicInfo
}

func NewClientKeyExchange(ctx HandShakeContext) ClientKeyExchange {

	var newX xClientKeyExchange

	if ctx == nil {
		return nil
	}

	newX.ctx = ctx
	return &newX
}

func (x *xClientKeyExchange) Name() string {
	return "_ClientKeyExchange_"
}

func (x *xClientKeyExchange) Next() (int, error) {
	x.Handle(nil)
	return x.nextState, x.nextError
}

func (x *xClientKeyExchange) Handle(data []byte) error {
	return nil
}
