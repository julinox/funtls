package cipherspec

/*

 */

import (
	"encoding/binary"
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/suite"
)

type GenericBlockCipher struct {
	IV            []byte
	BlockCiphered []byte
	Mac           []byte
}

type CipherSpec interface {
	SeqNumber() uint64
	SeqNumIncrement() error
	EncryptRec(tlssl.ContentTypeType, []byte) ([]byte, error)
	DecryptRec([]byte) ([]byte, error)
}

type xCS struct {
	macMode     int
	keys        *tlssl.Keys
	seqNum      uint64
	cipherSuite suite.Suite
}

func NewCipherSpec(cs suite.Suite, keys *tlssl.Keys, mode int) CipherSpec {

	var newSpec xCS

	if cs == nil || keys == nil {
		return nil
	}

	switch mode {
	case tlssl.MODE_MTE:
		newSpec.macMode = tlssl.MODE_MTE
	case tlssl.MODE_ETM:
		newSpec.macMode = tlssl.MODE_ETM
	default:
		return nil
	}

	newSpec.seqNum = 0
	newSpec.keys = keys
	newSpec.cipherSuite = cs
	return &newSpec
}

func (x *xCS) SeqNumber() uint64 {
	return x.seqNum
}

func (x *xCS) SeqNumIncrement() error {

	if x.seqNum == ^uint64(0) {
		return fmt.Errorf("sequence number overflow")
	}

	x.seqNum++
	return nil
}

// Returns a buffer ready to send into the wire.
// Contains the TLS header, the ciphered data and the MAC.
// 'pt' is the plaintext to cipher
func (x *xCS) EncryptRec(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	switch x.macMode {
	case tlssl.MODE_MTE:
		return x.encryptMTE(ct, pt)
	case tlssl.MODE_ETM:
		return x.encryptETM(ct, pt)
	}

	return nil, fmt.Errorf("unknown MAC mode for EncryptRec: %d", x.macMode)
}

func (x *xCS) DecryptRec(record []byte) ([]byte, error) {

	switch x.macMode {
	case tlssl.MODE_MTE:
		return x.decryptMTE(record)
	case tlssl.MODE_ETM:
		return x.decryptETM(record)
	}

	return nil, fmt.Errorf("unknown MAC mode for DecryptRec: %d", x.macMode)
}

// After ChangeCipherSpec, all TLS records are encrypted and sent with
// ContentType 0x17 (application_data) in the TLS record header.
//
// When MacMode is MTE, the MAC iscomputed using the original logical
// ContentType, depending on the message:
// - 0x16 for handshake messages (e.g. Finished)
// - 0x15 for alerts (e.g. close_notify)
// - 0x17 for application data
// This results in two conceptual headers per record:
// - TLSHeaderFinal: actual header sent on the wire (always 0x17 post-CCS)
// - TLSHeaderForMAC: header used internally for MAC computation
//
// When MacMode is ETM, the MAC is computed using the
// TLSHeaderFinal, which is always 0x17 after ChangeCipherSpec.

func (x *xCS) macOS(ct tlssl.ContentTypeType, data []byte) ([]byte, error) {

	var macData []byte
	var macTLSHeader tlssl.TLSHeader

	myself := systema.MyName()
	switch ct {
	case tlssl.ContentTypeHandshake,
		tlssl.ContentTypeAlert,
		tlssl.ContentTypeApplicationData:
		break

	default:
		return nil, fmt.Errorf("invalid ContentType(%v): %d", myself, ct)
	}

	macTLSHeader.ContentType = tlssl.ContentTypeApplicationData
	macTLSHeader.Version = tlssl.TLS_VERSION1_2
	macTLSHeader.Len = len(data)
	if x.macMode == tlssl.MODE_MTE {
		macTLSHeader.ContentType = ct
	}

	macData = append(macData, seqNumToBytes(x.seqNum)...)
	macData = append(macData, tlssl.TLSHeadPacket(&macTLSHeader)...)
	macData = append(macData, data...)
	return x.cipherSuite.MacMe(macData, x.keys.MAC)
}

func seqNumToBytes(sn uint64) []byte {
	seqNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqNumBytes, sn)
	return seqNumBytes
}
