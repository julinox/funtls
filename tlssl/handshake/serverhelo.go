package handshake

type ServerHello interface {
	Handle(*MsgHello) error
}
