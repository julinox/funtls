package tlssl

import (
	"encoding/binary"
	"fmt"
	"tlesio/tlssl/suite"
)

// Mac mode
const (
	MODE_MTE = iota + 1
	MODE_ETM
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
	IV(*TLSCipherText) []byte
	Content(*TLSCipherText) []byte
	MAC(*TLSCipherText) []byte
}

type xTLSCipherSpec struct {
	macMode     int
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
	case MODE_ETM:
		newTLSCT.macMode = MODE_ETM
	case MODE_MTE:
		newTLSCT.macMode = MODE_MTE
	default:
		return nil
	}

	newTLSCT.cipherSuite = cs
	newTLSCT.keys = keys
	return &newTLSCT
}

func (x *xTLSCipherSpec) CipherType() int {
	return x.cipherSuite.Info().CipherType
}

func (x *xTLSCipherSpec) Encode() ([]byte, error) {
	return nil, nil
}

// Deciper and format
func (x *xTLSCipherSpec) Decode(data []byte) (*TLSCipherText, error) {

	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil, fmt.Errorf("stream cipher not implemented")
	case suite.CIPHER_CBC:
		return x.cbc(data)
	case suite.CIPHER_AEAD:
		return nil, fmt.Errorf("AEAD cipher not implemented")
	}

	return nil, fmt.Errorf("unknown cipher type")
}

func (x *xTLSCipherSpec) IV(tct *TLSCipherText) []byte {

	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil
	case suite.CIPHER_CBC:
		return tct.Fragment.(*GenericBlockCipher).IV
	case suite.CIPHER_AEAD:
		return nil
	}

	return nil
}

func (x *xTLSCipherSpec) Content(tct *TLSCipherText) []byte {

	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil
	case suite.CIPHER_CBC:
		return tct.Fragment.(*GenericBlockCipher).Content
	case suite.CIPHER_AEAD:
		return nil
	}

	return nil
}

func (x *xTLSCipherSpec) MAC(tct *TLSCipherText) []byte {

	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil
	case suite.CIPHER_CBC:
		return tct.Fragment.(*GenericBlockCipher).Mac
	case suite.CIPHER_AEAD:
		return nil
	}

	return nil
}

func seqNumToBytes(sn uint64) []byte {
	seqNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumBytes, sn)
	return seqNumBytes
}
