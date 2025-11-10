package suite

import (
	"fmt"

	pki "github.com/julinox/funtls/tlssl/certpki"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/sirupsen/logrus"
)

type SuiteContext struct {
	Key  []byte
	HKey []byte
	IV   []byte
	Data []byte
}

type SuiteInfo struct {
	Mac         int // MAC algorithm
	CipherType  int
	Hash        int
	HashSize    int
	Cipher      int
	KeySize     int
	KeySizeHMAC int
	IVSize      int
	KeyExchange int
	Auth        int // Signature algorithm
}

type CertMatch struct {
	SG  []uint16
	SA  []uint16
	SNI []string
}

type SuiteOpts struct {
	IsClient bool
	Pki      pki.CertPKI
	Lg       *logrus.Logger
}

type Suite interface {
	ID() uint16
	Name() string
	Info() *SuiteInfo
	CertMe(*CertMatch) []byte
	HashMe([]byte) ([]byte, error)
	MacMe([]byte, []byte) ([]byte, error)
	Cipher(*SuiteContext) ([]byte, error)
	CipherNot(*SuiteContext) ([]byte, error)
	SignThis([]byte) []byte
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
	str += fmt.Sprintf("Auth: %s\n", signatureToString(info.Auth))
	str += fmt.Sprintf("KeyExchange: %s",
		keyExchangeToString(info.KeyExchange))
	return str
}

func keyExchangeToString(keyExchange int) string {

	switch keyExchange {
	case names.KX_RSA:
		return "RSA"
	case names.KX_ECDHE:
		return "ECDHE"
	case names.KX_ECDH:
		return "ECDH"
	case names.KX_DH:
		return "DH"
	case names.KX_DHE:
		return "DHE"
	}

	return "Unknown"
}

func signatureToString(signature int) string {
	switch signature {
	case names.SIG_RSA:
		return "RSA"
	case names.SIG_DSS:
		return "DSA"
	case names.SIG_ECDSA:
		return "ECDSA"
	}

	return "Unknown"
}

func cipherToString(cipher int) string {

	switch cipher {
	case names.CIPHER_AES:
		return "AES"
	case names.CIPHER_CHACHA20:
		return "CHACHA20"
	case names.CIPHER_3DES:
		return "3DES"
	case names.CIPHER_RC4:
		return "RC4"
	}

	return "Unknown"
}

func hashToString(hash int) string {

	switch hash {
	case names.HASH_SHA1:
		return "SHA1"
	case names.HASH_SHA256:
		return "SHA256"
	case names.HASH_SHA384:
		return "SHA384"
	case names.HASH_SHA512:
		return "SHA512"
	case names.HASH_MD5:
		return "MD5"
	}

	return "Unknown"
}

func modeToString(cipherType int) string {

	switch cipherType {
	case names.CIPHER_STREAM:
		return "STREAM"
	case names.CIPHER_CBC:
		return "CBC"
	case names.CIPHER_AEAD:
		return "AEAD"
	}

	return "Unknown"
}
