package tlssl

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"tlesio/systema"
	"tlesio/tlssl/suite"
)

// Mac mode
const VERIFYDATALEN = 12

const (
	MODE_MTE = iota + 1
	MODE_ETM
)

type GenericStreamCipher struct {
}

type GeneriAEADCipher struct {
}

type GenericBlockCipher struct {
	IV            []byte
	BlockCiphered []byte
	Mac           []byte
}

type TLSCipherText struct {
	Header   *TLSHeader
	Fragment interface{}
}

type TLSPlaintext struct {
	Header   *TLSHeader
	Fragment []byte
}

type TLSCipherSpec interface {
	CipherType() int
	Encode([]byte) ([]byte, error)
	Decode([]byte) (*TLSCipherText, error)
	EncryptRecord(*TLSPlaintext) (*TLSCipherText, error)
	Macintosh([]byte) ([]byte, error)
	Content(*TLSCipherText) []byte
}

type xTLSCSpec struct {
	macMode     int
	keys        *Keys
	seqNum      uint64
	cipherSuite suite.Suite
}

func NewTLSCipherSpec(cs suite.Suite, keys *Keys, mode int) TLSCipherSpec {

	var newTLSCT xTLSCSpec

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

func (x *xTLSCSpec) CipherType() int {
	return x.cipherSuite.Info().CipherType
}

func (x *xTLSCSpec) Encode(data []byte) ([]byte, error) {

	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil, fmt.Errorf("stream cipher not implemented")
	case suite.CIPHER_CBC:
		return x.encodeCBC(data)
	case suite.CIPHER_AEAD:
		return nil, fmt.Errorf("AEAD cipher not implemented")
	}

	return nil, fmt.Errorf("encode unknown cipher type")
}

func (x *xTLSCSpec) Decode(data []byte) (*TLSCipherText, error) {

	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil, fmt.Errorf("stream cipher not implemented")
	case suite.CIPHER_CBC:
		return x.decodeCBC(data)
	case suite.CIPHER_AEAD:
		return nil, fmt.Errorf("AEAD cipher not implemented")
	}

	return nil, fmt.Errorf("decode unknown cipher type")
}

func (x *xTLSCSpec) EncryptRecord(tpt *TLSPlaintext) (*TLSCipherText, error) {

	myself := systema.MyName()
	if tpt == nil || tpt.Header == nil {
		return nil, fmt.Errorf("nil TLSPlaintext(%v)", myself)
	}

	if x.seqNum == 0 {
		if tpt.Header.ContentType != ContentTypeHandshake {
			return nil, fmt.Errorf("invalid ContentType(%v)", myself)
		}

		if len(tpt.Fragment) != TLS_HANDSHAKE_SIZE+VERIFYDATALEN {
			return nil, fmt.Errorf("(%v)", myself)
		}
	}

	switch x.macMode {
	case MODE_ETM:
		return x.encryptRecordETM(tpt)
	case MODE_MTE:
		return x.encryptRecordMTE(tpt)
	}

	return nil, fmt.Errorf("no MAC-Mode match(%v)", myself)
}

// calculate MAC
// MAC(MAC_write_key, seq_num + TLSCompressed.type +
// TLSCompressed.version + TLSCompressed.length +
// TLSCompressed.fragment)
func (x *xTLSCSpec) Macintosh(data []byte) ([]byte, error) {

	var macData []byte
	var header TLSHeader

	header.ContentType = ContentTypeApplicationData
	header.Version = TLS_VERSION1_2
	header.Len = len(data)
	if x.seqNum == 0 {
		header.ContentType = ContentTypeHandshake
	}

	macData = append(macData, seqNumToBytes(x.seqNum)...)
	macData = append(macData, TLSHeadPacket(&header)...)
	macData = append(macData, data...)
	return x.cipherSuite.MacMe(macData, x.keys.MAC)
}

// TLSCipherText
func (xt *TLSCipherText) Packet(fragType int, skipIv bool) ([]byte, error) {

	var iv []byte
	var content []byte

	switch fragType {
	case suite.CIPHER_STREAM:
		return nil, fmt.Errorf("stream cipher not implemented")

	case suite.CIPHER_CBC:
		aux, ok := xt.Fragment.(*GenericBlockCipher)
		if !ok {
			return nil, fmt.Errorf("invalid fragment type")
		}

		iv = aux.IV
		content = aux.BlockCiphered

	case suite.CIPHER_AEAD:
		return nil, fmt.Errorf("AEAD cipher not implemented")
	}

	packet := TLSHeadPacket(xt.Header)
	if !skipIv {
		fmt.Println("----------------------- DEBUG PACKET -----------------------")
		packet = append(packet, iv...)
	}

	return append(packet, content...), nil
}

// ----------------------------------------------------------------------
func (x *xTLSCSpec) Content(tct *TLSCipherText) []byte {

	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil
	case suite.CIPHER_CBC:
		return tct.Fragment.(*GenericBlockCipher).BlockCiphered
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

func generateIVNonce(sz int) ([]byte, error) {

	iv := make([]byte, sz)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}

	return iv, nil
}
