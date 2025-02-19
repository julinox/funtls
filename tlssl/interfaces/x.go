package interfaces

// manage client key exchange message

type CliKeyExchange interface {
	Handle([]byte) error
}

type xCliKeyExchange struct {
}

func NewIfCliKeyExchange() CliKeyExchange {
	return &xCliKeyExchange{}
}

func (cke *xCliKeyExchange) Handle(buff []byte) error {

	return nil
}
