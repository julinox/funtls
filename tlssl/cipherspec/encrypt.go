package cipherspec

import (
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/suite"
)

func (x *xCS) encryptRec(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	var err error
	var record []byte

	if x.cipherSuite.Info().CipherType == suite.CIPHER_CBC {
		switch x.macMode {
		case tlssl.MODE_MTE:
			record, err = x.encryptMTE(ct, pt)

		case tlssl.MODE_ETM:
			record, err = x.encryptETM(ct, pt)

		default:
			return nil, fmt.Errorf("unsupported macMode: %v", x.macMode)
		}

	} else if x.cipherSuite.Info().CipherType == suite.CIPHER_AEAD {
		record, err = x.encryptAEAD()

	} else {
		return nil, fmt.Errorf("unsupported CipherType: %v",
			x.cipherSuite.Info().CipherType)
	}

	return record, err
}

// 'fragment' is the final encrypted data (without the TLS header)
// The name 'fragment' comes from RFC 5246, section 6.2.3 (TLSCiphertext)

// When seqnum is zero it means we are dealing with the FINISHED message
// which (based on observation) has the following implications:
//   - The IV to use is the derived one (x.keys.IV).
//   - The first IV-Sized bytes of the encrypted message are random bytes,
//   - MAC is calculated over the plaintext (HandshakeHeader + verified data).
//   - No IV preceding the ciphertext.
//   - Final TLS record is: [TLSHEADER | E( IV | pt | MAC)], where pt is
//     HandshakeHeader + verified data
func (x *xCS) encryptMTE(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	var err error
	var fragment []byte
	var sCtx suite.SuiteContext

	myself := systema.MyName()
	if len(pt) == 0 {
		return nil, fmt.Errorf("empty plaintext (%v)", myself)
	}

	mac, err := x.macOS(ct, pt)
	if err != nil {
		return nil, fmt.Errorf("macOS(%v): %v", myself, err)
	}

	iv, err := generateIVNonce(x.cipherSuite.Info().IVSize)
	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = append(sCtx.Data, iv...)
	} else {
		sCtx.IV = iv
	}

	sCtx.Key = x.keys.Key
	sCtx.Data = append(sCtx.Data, pt...)
	sCtx.Data = append(sCtx.Data, mac...)
	fragment, err = x.cipherSuite.Cipher(&sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: ct,
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(fragment),
	})

	return append(header, fragment...), nil
}

func (x *xCS) encryptETM(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	fmt.Println("CBC ETM")
	return nil, nil
}

func (x *xCS) encryptAEAD() ([]byte, error) {

	fmt.Println("AEAD")
	return nil, nil
}
