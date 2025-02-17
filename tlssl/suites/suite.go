package suites

import "fmt"

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
}

func (sc *SuiteContext) Printea() string {

	return fmt.Sprintf("IV: %s\nKey: %s\nHKey: %s\nData: %s\nMacMode: %s",
		sc.IV, sc.Key, sc.HKey, sc.Data, macModeToString(sc.MacMode))
}

func macModeToString(macMode int) string {
	switch macMode {
	case MTE:
		return "MTE"
	case AEAD:
		return "AEAD"
	}

	return "ETM"
}
