package suite

import (
	"fmt"
)

// Names for ciphers, hash functions, and key exchange algorithms
const (
	AES = iota + 1
	CHACHA20

	HMAC
	POLY1305

	SHA1
	SHA256
	SHA384

	RSA
	DHE
)

// Cipher Types
const (
	CIPHER_STREAM = iota + 1
	CIPHER_CBC
	CIPHER_AEAD
)

type SuiteContext struct {
	Key  []byte
	HKey []byte
	IV   []byte
	Data []byte
}

type SuiteInfo struct {
	Mac         int
	CipherType  int
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
	MacMe([]byte, []byte) ([]byte, error) // (data, hashkey)
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

	str += fmt.Sprintf("CipherType: %s\n", modeToString(info.CipherType))
	str += fmt.Sprintf("HashName: %s\n", hashToString(info.Hash))
	str += fmt.Sprintf("CipherName: %s\n", cipherToString(info.Cipher))
	str += fmt.Sprintf("KeySize: %d\n", info.KeySize)
	str += fmt.Sprintf("KeySizeHMAC: %d\n", info.KeySizeHMAC)
	str += fmt.Sprintf("IVSize: %d\n", info.IVSize)
	str += fmt.Sprintf("KeyExchange: %s",
		keyExchangeToString(info.KeyExchange))
	return str
}

func modeToString(cipherType int) string {

	switch cipherType {
	case CIPHER_STREAM:
		return "STREAM"
	case CIPHER_CBC:
		return "CBC"
	case CIPHER_AEAD:
		return "AEAD"
	}

	return "Unknown"
}

func hashToString(hash int) string {

	switch hash {
	case SHA1:
		return "SHA1"
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
