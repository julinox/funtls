package handshake

const (
	CERTIFICATE        = 1 << 0
	CERTIFICATEREQUEST = 1 << 1
	CHANGECIPHERSPEC   = 1 << 2
	CLIENTHELLO        = 1 << 3
	CLIENTKEYEXCHANGE  = 1 << 4
	FINISHED           = 1 << 5
	SERVERHELLO        = 1 << 6
	SERVERHELLODONE    = 1 << 7
	SERVERKEYEXCHANGE  = 1 << 8
)

type Handshake interface {
	ClientHello([]byte) error
}
