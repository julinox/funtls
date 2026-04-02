package cipherspec

import (
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/julinox/funtls/tlssl/suite"
)

func (x *xCS) encryptRec(dst, src []byte, ct uint8) ([]byte, error) {

	var err error
	var record []byte

	if x.cipherSuite.Info().CipherType == names.CIPHER_CBC {
		switch x.macMode {
		case tlssl.MODE_MTE:
			record, err = x.encryptMTE(dst, src, ct)

		case tlssl.MODE_ETM:
			record, err = x.encryptETM(dst, src, ct)

		default:
			return nil, fmt.Errorf("unsupported macMode: %v", x.macMode)
		}

	} else if x.cipherSuite.Info().CipherType == names.CIPHER_AEAD {
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
func (x *xCS) encryptMTE(dst, src []byte, ct uint8) ([]byte, error) {

	var err error

	myself := systema.MyName()
	if len(src) == 0 {
		return nil, fmt.Errorf("empty plaintext (%v)", myself)
	}

	ivSz := x.cipherSuite.Info().IVSize
	if cap(dst) < tlssl.TLS_HEADER_SIZE+ivSz {
		return nil, fmt.Errorf("dst capacity is too smal for buffer")
	}

	iv, err := generateIVNonce(ivSz)
	if err != nil {
		return nil, fmt.Errorf("generateIVNonce(%v): %v", myself, err)
	}

	mac, err := x.macintosh(src, ct)
	if err != nil {
		return nil, fmt.Errorf("macOS(%v): %v", myself, err)
	}

	data := &mteEtm{iv, mac, dst, src}
	if x.seqNum == 0 {
		return x.encryptMTESN0(data, ct)
	}

	return x.encryptMTESNN(data, ct)
}

func (x *xCS) encryptETM(dst, src []byte, ct uint8) ([]byte, error) {

	var err error
	var fragment []byte
	var sCtx suite.SuiteContext

	myself := systema.MyName()
	if len(src) == 0 {
		return nil, fmt.Errorf("empty plaintext (%v)", myself)
	}

	iv, err := generateIVNonce(x.cipherSuite.Info().IVSize)
	if err != nil {
		return nil, fmt.Errorf("generateIVNonce(%v): %v", myself, err)
	}

	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = append(sCtx.Data, iv...)
	} else {
		sCtx.IV = iv
		fragment = append(fragment, iv...)
	}

	sCtx.Key = x.keys.Key
	//sCtx.Data = append(sCtx.Data, src...)
	ciphered, err := x.cipherSuite.Cipher(nil, nil, &sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	fragment = append(fragment, ciphered...)
	mac, err := x.macintosh(fragment, ct)
	if err != nil {
		return nil, fmt.Errorf("macOS(%v): %v", myself, err)
	}

	fragment = append(fragment, mac...)
	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: tlssl.ContentTypeType(ct),
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(fragment),
	})

	return append(header, fragment...), nil
}

func (x *xCS) encryptAEAD() ([]byte, error) {
	return nil, fmt.Errorf("encryptAEAD not implemented yet")
}
