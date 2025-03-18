package suite

import (
	"fmt"
)

const (
	AES = iota + 1
	CHACHA20

	CBC
	GCM
	STREAM

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
)

type SuiteContext struct {
	Key  []byte
	HKey []byte
	IV   []byte
	Data []byte
}

type SuiteInfo struct {
	Mac         int
	Mode        int
	Hash        int
	HashSize    int
	Cipher      int
	KeySize     int
	KeySizeHMAC int
	IVSize      int
	KeyExchange int
	Auth        int
}

type Suite interface {
	ID() uint16
	Name() string
	Info() *SuiteInfo
	Cipher(*SuiteContext) ([]byte, error)
	CipherNot(*SuiteContext) ([]byte, error)
	MacMe([]byte, []byte) ([]byte, error)
	HashMe([]byte) ([]byte, error)
}

func (sc *SuiteContext) Print() string {

	return fmt.Sprintf("IV: %s\nKey: %s\nHKey: %s\nData: %s",
		sc.IV, sc.Key, sc.HKey, sc.Data)
}

func (sc *SuiteContext) PrintRaw() string {

	return fmt.Sprintf("IV: %x\nKey: %x\nHKey: %x\nData: %x",
		sc.IV, sc.Key, sc.HKey, sc.Data)
}

func (info *SuiteInfo) Print() string {

	var str string

	str += fmt.Sprintf("MAC: %s\n", macModeToString(info.Mac))
	str += fmt.Sprintf("Mode: %s\n", modeToString(info.Mode))
	str += fmt.Sprintf("Hash: %s\n", hashToString(info.Hash))
	str += fmt.Sprintf("Cipher: %s\n", cipherToString(info.Cipher))
	str += fmt.Sprintf("KeySize: %d\n", info.KeySize)
	str += fmt.Sprintf("KeySizeHMAC: %d\n", info.KeySizeHMAC)
	str += fmt.Sprintf("IVSize: %d\n", info.IVSize)
	str += fmt.Sprintf("KeyExchange: %s",
		keyExchangeToString(info.KeyExchange))
	return str
}

func macModeToString(macMode int) string {

	switch macMode {
	case MTE:
		return "MTE"
	case ETM:
		return "ETM"
	}

	return "UnknownMacMode"
}

func modeToString(mode int) string {

	switch mode {
	case CBC:
		return "CBC"
	case GCM:
		return "GCM"
	}

	return "Unknown"
}

func hashToString(hash int) string {

	switch hash {
	case SHA:
		return "SHA"
	case SHA256:
		return "SHA256"
	case SHA384:
		return "SHA384"
	}

	return "Unknown"
}

func cipherToString(cipher int) string {

	switch cipher {
	case AES:
		return "AES"
	case CHACHA20:
		return "CHACHA20"
	}

	return "Unknown"
}

func keyExchangeToString(keyExchange int) string {

	switch keyExchange {
	case RSA:
		return "RSA"
	case DHE:
		return "DHE"
	}

	return "Unknown"
}
