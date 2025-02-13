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
)

type CipherContext struct {
	IV   []byte
	Key  []byte
	Text []byte
}

type SuiteInfo struct {
	Mac     int
	Mode    int
	Hash    int
	Cipher  int
	KeySize int
}

type Suite interface {
	ID() uint16
	Name() string
	Cipher(*CipherContext) error
	CipherNot(*CipherContext) error
	MacMe()
}
