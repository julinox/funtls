package cipherspec

import (
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/suite"
)

// opaque is the final decrypted data (without the TLS header)
// The name 'opaque' comes from RFC 5246, section 6.2.1 (struct TLSPlaintext{)
func (x *xCS) decryptRec(ct []byte) ([]byte, error) {

	var err error
	var opaque []byte
	var tRec *tlssl.TLSRecord

	tRec, err = tlssl.TLSRecordMe(ct)
	if err != nil || tRec == nil {
		return nil, fmt.Errorf("TLSRecordMe error: %v", err)
	}

	if x.cipherSuite.Info().CipherType == suite.CIPHER_CBC {
		switch x.macMode {
		case tlssl.MODE_MTE:
			opaque, err = x.decryptMTE(tRec)

		case tlssl.MODE_ETM:
			opaque, err = x.decryptETM(tRec)

		default:
			return nil, fmt.Errorf("unsupported macMode: %v", x.macMode)
		}

	} else if x.cipherSuite.Info().CipherType == suite.CIPHER_AEAD {
		opaque, err = x.decryptAEAD(ct)

	} else {
		return nil, fmt.Errorf("unsupported CipherType: %v",
			x.cipherSuite.Info().CipherType)
	}

	if err != nil {
		return nil, err
	}

	return opaque, nil
}

// Decrypts a TLS record using the MTE (MAC-then-Encrypt) mode.
// It extracts the IV and the ciphertext from the TLS record.
//
// When the sequence number is zero it means we are dealing with the
// finished message, thus the IV is not present in the record and the
// ciphertext is the entire message. Also its important to mention that
// at least in MTE mode the first IV-Sized bytes of the decrypted message
// are (based on observation) random bytes, the rest is handshake-header +
// verified data + MAC.
func (x *xCS) decryptMTE(tRec *tlssl.TLSRecord) ([]byte, error) {

	var sCtx suite.SuiteContext

	myself := systema.MyName()
	sCtx.Key = x.keys.Key
	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = tRec.Msg
	} else {
		sCtx.IV = tRec.Msg[:x.cipherSuite.Info().IVSize]
		sCtx.Data = tRec.Msg[x.cipherSuite.Info().IVSize:]
	}

	fmt.Println("HEADER: ", tRec.Header)
	clearText, err := x.cipherSuite.CipherNot(&sCtx)
	if err != nil {
		return nil, fmt.Errorf("%v: %v", myself, err)
	}

	return nil, nil
}

func (x *xCS) decryptETM(tRec *tlssl.TLSRecord) ([]byte, error) {
	return nil, nil
}

func (x *xCS) decryptAEAD(ct []byte) ([]byte, error) {
	return nil, nil
}
