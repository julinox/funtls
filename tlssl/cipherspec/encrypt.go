package cipherspec

import (
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/suite"
)

// fragment is the final encrypted data (without the TLS header)
// The name 'fragment' comes from RFC 5246, section 6.2.3 (TLSCiphertext)
func (x *xCS) encrypRec(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	var err error
	var fragment []byte

	if x.cipherSuite.Info().CipherType == suite.CIPHER_CBC {
		switch x.macMode {
		case tlssl.MODE_MTE:
			fragment, err = x.encryptMTE(ct, pt)

		case tlssl.MODE_ETM:
			fragment, err = x.encryptETM(ct, pt)

		default:
			return nil, fmt.Errorf("unsupported macMode: %v", x.macMode)
		}

	} else if x.cipherSuite.Info().CipherType == suite.CIPHER_AEAD {
		fragment, err = x.encryptAEAD()

	} else {
		return nil, fmt.Errorf("unsupported CipherType: %v",
			x.cipherSuite.Info().CipherType)
	}

	if err != nil {
		return nil, err
	}

	header := tlssl.TLSHeadPacket(&tlssl.TLSHeader{
		ContentType: ct,
		Version:     tlssl.TLS_VERSION1_2,
		Len:         len(fragment),
	})

	return append(header, fragment...), nil
}

func (x *xCS) encryptMTE(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	var err error
	var sCtx suite.SuiteContext

	myself := systema.MyName()
	mac, err := x.macOS(ct, pt)
	if err != nil {
		return nil, fmt.Errorf("macOS(%v): %v", myself, err)
	}

	iv, err := generateIVNonce(x.cipherSuite.Info().IVSize)
	if err != nil {
		return nil, fmt.Errorf("IV generation(%v): %v", myself, err)
	}

	sCtx.IV = iv
	sCtx.Key = x.keys.Key
	// If seqnum == 0 that means we are dealing with the 'Finished'
	// message (so we use the IV derived from the session keys).
	// Also, we prepend some random (IV-Sized) data. The reason
	// is to be found out, but it seems to be a requirement (based on
	// observation) for the CBC cipher to work properly.
	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = append(sCtx.Data, iv...)
	}

	sCtx.Data = append(sCtx.Data, pt...)
	sCtx.Data = append(sCtx.Data, mac...)
	return x.cipherSuite.Cipher(&sCtx)
}

func (x *xCS) encryptETM(ct tlssl.ContentTypeType, pt []byte) ([]byte, error) {

	fmt.Println("CBC ETM")
	return nil, nil
}

func (x *xCS) encryptAEAD() ([]byte, error) {

	fmt.Println("AEAD")
	return nil, nil
}
