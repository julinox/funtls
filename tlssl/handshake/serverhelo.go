package handshake

type ServerHello interface {
	Handle(*MsgCliHello) error
}
