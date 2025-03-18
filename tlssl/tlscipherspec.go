package tlssl

import (
	"encoding/binary"
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

type TLSCipherText struct {
	Header   *TLSHeader
	Fragment interface{}
}

type TLSCipherSpec interface {
	CipherType() int
	Encode() ([]byte, error)
	Decode([]byte) (*TLSCipherText, error)
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

func (x *xTLSCipherSpec) CipherType() int {
	return x.cipherSuite.Info().Mode
}

func (x *xTLSCipherSpec) Encode() ([]byte, error) {
	return nil, nil
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

func seqNumToBytes(sn uint64) []byte {
	seqNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumBytes, sn)
	return seqNumBytes
}
