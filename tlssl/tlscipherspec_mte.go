package tlssl

import (
	"crypto/hmac"
	"fmt"
	"tlesio/systema"
	"tlesio/tlssl/suite"
)

func (x *xTLSCSpec) encryptMTE(tpt *TLSPlaintext) (*TLSCipherText, error) {

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
	ciphered, err := x.cipherSuite.Cipher(&sCtx)
	if err != nil {
		return nil, fmt.Errorf("Ciphering(%v): %v", myself, err)
	}

	tct.Header = &TLSHeader{
		ContentType: tpt.Header.ContentType,
		Version:     TLS_VERSION1_2,
		Len:         len(ciphered),
	}

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

func (x *xTLSCSpec) decryptMTE(tct *TLSCipherText) (*TLSPlaintext, error) {

	var err error
	var tpt TLSPlaintext
	var iv, cipherText []byte

	myself := systema.MyName()
	cipherRecord, ok := tct.Fragment.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid fragment buffer type(%v)", myself)
	}

	if len(cipherRecord) <= x.cipherSuite.Info().IVSize {
		return nil, fmt.Errorf("decrypt short data(%v)", myself)
	}

	cipherText = cipherRecord[x.cipherSuite.Info().IVSize:]
	iv = cipherRecord[:x.cipherSuite.Info().IVSize]
	if x.seqNum == 0 {
		iv = x.keys.IV
		cipherText = cipherRecord
	}

	sCtx := suite.SuiteContext{
		IV:   iv,
		Key:  x.keys.Key,
		Data: cipherText,
	}

	clearText, err := x.cipherSuite.CipherNot(&sCtx)
	if err != nil {
		return nil, fmt.Errorf("decipher(%v): %v", myself, err)
	}

	hashSz := x.cipherSuite.Info().HashSize
	if len(clearText) < hashSz {
		return nil, fmt.Errorf("decipher short data(%v)", myself)
	}

	plainText := clearText[:len(clearText)-hashSz]
	givenMAC := clearText[len(clearText)-hashSz:]
	if x.seqNum == 0 {
		plainText = plainText[x.cipherSuite.Info().IVSize:]
	}

	computedMAC, err := x.Macintosh(plainText)
	if err != nil {
		return nil, fmt.Errorf("MAC calculation(%v): %v", myself, err)
	}

	if !hmac.Equal(givenMAC, computedMAC) {
		return nil, fmt.Errorf("MAC mismatch(%v)", myself)
	}

	tpt.Fragment = plainText
	tpt.Header = &TLSHeader{
		ContentType: tct.Header.ContentType,
		Version:     TLS_VERSION1_2,
		Len:         len(plainText),
	}

	return &tpt, nil
}
