package tlssl

import (
	"fmt"
	"tlesio/tlssl/suite"
)

const (
	CIPHER_STREAM = iota + 1
	CIPHER_CBC
	CIPHER_AEAD
)

type GenericStreamCipher struct {
}

type GeneriAEADCipher struct {
}

type GenericBlockCipher struct {
	IV      []byte
	Content []byte
	Mac     []byte
}

type TLSFragment struct {
	Fragment interface{}
}

type TLSCipherText struct {
	Header   *TLSHeader
	Fragment *TLSFragment
}

type TLSCipherSpec interface {
	//Header() *TLSHeader
	//Fragment() *TLSFragment
	Decode([]byte) (*TLSCipherText, error)
	CipherType() int
	//Encode() ([]byte, error)
}

type xTLSCipherSpec struct {
	cipherMode  int
	keys        *Keys
	seqNum      uint64
	cipherSuite suite.Suite
}

func NewTLSCipherSpec(cs suite.Suite, keys *Keys, mode int) TLSCipherSpec {

	var newTLSCT xTLSCipherSpec

	if cs == nil || keys == nil {
		return nil
	}

	switch mode {
	case suite.ETM:
		newTLSCT.cipherMode = suite.ETM
	case suite.MTE:
		newTLSCT.cipherMode = suite.MTE
	default:
		return nil
	}

	newTLSCT.cipherSuite = cs
	newTLSCT.keys = keys
	return &newTLSCT
}

// Deciper and format
func (x *xTLSCipherSpec) Decode(data []byte) (*TLSCipherText, error) {

	switch x.cipherSuite.Info().Mode {
	case suite.STREAM:
		return nil, fmt.Errorf("stream cipher not implemented")
	case suite.CBC:
		return x.cbc(data)
	case suite.GCM:
		return nil, fmt.Errorf("AEAD cipher not implemented")
	}

	return nil, fmt.Errorf("unknown cipher type")
}

func (x *xTLSCipherSpec) CipherType() int {
	return x.cipherSuite.Info().Mode
}
