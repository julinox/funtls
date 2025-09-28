package cipherspec

import (
	"fmt"

	"crypto/hmac"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

// opaque is the final decrypted data (without the TLS header)
// The name 'opaque' comes from RFC 5246, section 6.2.1 (struct TLSPlaintext{)
func (x *xCS) decryptRec(record []byte) ([]byte, error) {

	var err error
	var opaque []byte
	var tRec *tlssl.TLSRecord

	tRec, err = tlssl.TLSRecordMe(record)
	if err != nil || tRec == nil {
		return nil, fmt.Errorf("TLSRecordMe error: %v", err)
	}

	if x.cipherSuite.Info().CipherType == names.CIPHER_CBC {
		switch x.macMode {
		case tlssl.MODE_MTE:
			opaque, err = x.decryptMTE(tRec)

		case tlssl.MODE_ETM:
			opaque, err = x.decryptETM(tRec)

		default:
			return nil, fmt.Errorf("unsupported macMode: %v", x.macMode)
		}

	} else if x.cipherSuite.Info().CipherType == names.CIPHER_AEAD {
		opaque, err = x.decryptAEAD(tRec)

	} else {
		return nil, fmt.Errorf("unsupported CipherType: %v",
			x.cipherSuite.Info().CipherType)
	}

	return opaque, err
}

// Decrypts a TLS record using the MTE (MAC-then-Encrypt) mode.
// It extracts the IV and the ciphertext from the TLS record.
//
// When seqnum is zero it means we are dealing with the FINISHED message
// which (based on observation) has the following implications:
//   - The IV is not present in the record (x.keys.IV is used instead)
//   - The entire message is the ciphertext (again theres no preceding IV).
//   - The first IV-Sized bytes of the decrypted message are random bytes,
//     the rest is HandshakeHeader + verified data + MAC.
//   - The MAC is computed over the HandshakeHeader and the verified data.
func (x *xCS) decryptMTE(tRec *tlssl.TLSRecord) ([]byte, error) {

	var sCtx suite.SuiteContext

	myself := systema.MyName()
	if len(tRec.Msg) < x.cipherSuite.Info().IVSize+
		x.cipherSuite.Info().HashSize {
		return nil, fmt.Errorf("Record shorter than IV+Hash size: %v", myself)
	}

	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = tRec.Msg
	} else {
		sCtx.IV = tRec.Msg[:x.cipherSuite.Info().IVSize]
		sCtx.Data = tRec.Msg[x.cipherSuite.Info().IVSize:]
	}

	sCtx.Key = x.keys.Key
	clearText, err := x.cipherSuite.CipherNot(&sCtx)
	if err != nil {
		return nil, fmt.Errorf("%v: %v", myself, err)
	}

	if len(clearText) < x.cipherSuite.Info().HashSize {
		return nil, fmt.Errorf("short data on deciphering(%v)", myself)
	}

	boundary := len(clearText) - x.cipherSuite.Info().HashSize
	givenMAC := clearText[boundary:]
	plainText := clearText[:boundary]
	if x.seqNum == 0 {
		plainText = plainText[x.cipherSuite.Info().IVSize:]
	}

	computedMAC, err := x.macintosh(tRec.Header.ContentType, plainText)
	if err != nil {
		return nil, fmt.Errorf("%v: %v", myself, err)
	}

	if !hmac.Equal(givenMAC, computedMAC) {
		return nil, fmt.Errorf("MAC mismatch(%v)", myself)
	}

	return plainText, nil
}

func (x *xCS) decryptETM(tRec *tlssl.TLSRecord) ([]byte, error) {

	var sCtx suite.SuiteContext

	myself := systema.MyName()
	if len(tRec.Msg) < x.cipherSuite.Info().IVSize+
		x.cipherSuite.Info().HashSize {
		return nil, fmt.Errorf("Record shorter than IV+Hash size: %v", myself)
	}

	givenMAC := tRec.Msg[len(tRec.Msg)-x.cipherSuite.Info().HashSize:]
	record := tRec.Msg[:len(tRec.Msg)-x.cipherSuite.Info().HashSize]
	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = record
	} else {
		sCtx.IV = tRec.Msg[:x.cipherSuite.Info().IVSize]
		sCtx.Data = record[x.cipherSuite.Info().IVSize:]
	}

	computedMAC, err := x.macintosh(tRec.Header.ContentType, record)
	if err != nil {
		return nil, fmt.Errorf("%v: %v", myself, err)
	}

	if !hmac.Equal(givenMAC, computedMAC) {
		return nil, fmt.Errorf("MAC mismatch(%v)", myself)
	}

	sCtx.Key = x.keys.Key
	clearText, err := x.cipherSuite.CipherNot(&sCtx)
	if err != nil {
		return nil, fmt.Errorf("%v: %v", myself, err)
	}

	if x.seqNum == 0 {
		return clearText[x.cipherSuite.Info().IVSize:], nil
	}

	return clearText, nil
}

func (x *xCS) decryptAEAD(tRec *tlssl.TLSRecord) ([]byte, error) {
	return nil, fmt.Errorf("decryptAEAD not implemented yet")
}
