package cipherspec

// When ciphersuite uses CBC (Cipher Block Chaining) the MAC
// (Message Authentication Code) is computed separately. That
// means that MAC mode (MTE/ETM) only happens on CBC ciphersuites.

// When ciphersuite uses AEAD (Authenticated Encryption with Associated Data),
// the MAC is included in the ciphertext, and the MAC computation
// is integrated into the encryption process. In this case, the MAC
// is not computed separately, and the MACMode does not affect the
// encryption/decryption process. The AEAD ciphersuite handles both
// encryption and MAC computation in a single step.
//
// Decrypt/Encryt functions validate several length of the input
// In general, the following rules apply:
//   * TLS Record must be at least TLS_HEADER_SIZE + LEN_SIZE
// CBC ciphersuites:
//   * Must have at least TLS_HEADER_SIZE + IV_SIZE + MAC_SIZE
//   * Decrypted data must be at least IV_SIZE + MAC_SIZE
// AEAD ciphersuites:
import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/suite"
)

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

// Returns a buffer containing a TLS encrypted record, ready to be
// send on the wire ('pt' means 'plaintext')
func (x *xCS) EncryptRec(t tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	record, err := x.encryptRec(t, pt)
	if err0 := x.SeqNumIncrement(); err0 != nil {
		return nil, err
	}

	return record, err
}

// Returns a buffer containing pure plaintext.
// 'ct' is the ciphertext to decipher
func (x *xCS) DecryptRec(ct []byte) ([]byte, error) {

	pt, err := x.decryptRec(ct)
	if err0 := x.SeqNumIncrement(); err0 != nil {
		return nil, err
	}

	return pt, err
}

// Returns a buffer containing the MAC calculated for the given data.
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
	return x.cipherSuite.MacMe(macData, x.keys.Hkey)
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
