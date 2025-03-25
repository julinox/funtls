package tlssl

import (
	"fmt"
	"tlesio/systema"
	"tlesio/tlssl/suite"
)

func (x *xTLSCSpec) encryptRecordMTE(tpt *TLSPlaintext) (*TLSCipherText, error) {

	var err error
	var tct TLSCipherText
	var sCtx suite.SuiteContext

	myself := systema.MyName()
	mac, err := x.Macintosh(tpt.Fragment)
	if err != nil {
		return nil, fmt.Errorf("MAC calculation(%v): %v", myself, err)
	}

	iv, err := generateIVNonce(x.cipherSuite.Info().IVSize)
	if err != nil {
		return nil, fmt.Errorf("IV generation(%v): %v", myself, err)
	}

	sCtx.Key = x.keys.Key
	sCtx.IV = iv
	if x.seqNum == 0 {
		sCtx.IV = x.keys.IV
		sCtx.Data = append(sCtx.Data, iv...)
	}

	sCtx.Data = append(sCtx.Data, tpt.Fragment...)
	sCtx.Data = append(sCtx.Data, mac...)
	fmt.Printf("ClearText(preciphered): %x\n", sCtx.Data)
	ciphered, err := x.cipherSuite.Cipher(&sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	fmt.Printf("%x | %x | %x\n", iv, tpt.Fragment, mac)
	fmt.Printf("Ciphered: %x\n", ciphered)
	tct.Header = &TLSHeader{
		ContentType: tpt.Header.ContentType,
		Version:     TLS_VERSION1_2,
		Len:         len(ciphered),
	}

	fmt.Printf("KEY / IV / HKEY: %x / %x / %x\n", x.keys.Key, x.keys.IV, x.keys.MAC)
	switch x.cipherSuite.Info().CipherType {
	case suite.CIPHER_STREAM:
		return nil, fmt.Errorf("stream cipher not implemented")

	case suite.CIPHER_CBC:
		tct.Fragment = &GenericBlockCipher{
			IV:            iv,
			BlockCiphered: ciphered,
		}

	case suite.CIPHER_AEAD:
		return nil, fmt.Errorf("AEAD cipher not implemented")
	}

	return &tct, nil
}
