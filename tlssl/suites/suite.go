package suites

const (
	AES = iota + 1
	CHACHA20

	CBC
	GCM

	HMAC
	POLY1305

	SHA
	SHA256
	SHA384

	RSA
	DHE
)

const (
	ETM = iota + 1
	MTE
	AEAD
)

type SuiteContext struct {
	IV      []byte
	Key     []byte
	HKey    []byte
	Data    []byte
	MacMode int
}

type SuiteInfo struct {
	Mac         int
	Mode        int
	Hash        int
	Cipher      int
	KeySize     int
	KeyExchange int
	Auth        int
}

type Suite interface {
	ID() uint16
	Name() string
	Info() *SuiteInfo
	Cipher(*SuiteContext) ([]byte, error)
	CipherNot(*SuiteContext) ([]byte, error)
	MacMe(*SuiteContext) ([]byte, error)
	//ETM(*SuiteContext) ([]byte, error)
	//MTE(*SuiteContext) ([]byte, error)
}
