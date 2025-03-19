package tlssl

import (
	"crypto/hmac"
	"fmt"
	"tlesio/systema"
	"tlesio/tlssl/suite"
)

/*
struct {
	ContentType type;
	ProtocolVersion version;
	uint16 length;
	select (SecurityParameters.cipher_type) {
		case stream: GenericStreamCipher;
		case block: GenericBlockCipher;
		case aead: GenericAEADCipher;
	} fragment;
} TLSCiphertext

 struct {
	opaque IV[SecurityParameters.record_iv_length];
	block-ciphered struct {
		opaque content[TLSCompressed.length];
		opaque MAC[SecurityParameters.mac_length];
		uint8 padding[GenericBlockCipher.padding_length];
		uint8 padding_length;
	};
} GenericBlockCipher;

MAC(MAC_write_key,
	seq_num +
	TLSCompressed.type +
	TLSCompressed.version +
	TLSCompressed.length +
	TLSCompressed.fragment);
*/

func (x *xTLSCipherSpec) cbc(data []byte) (*TLSCipherText, error) {

	var err error
	var tct *TLSCipherText

	// Decode the data
	myself := systema.MyName()
	switch x.macMode {
	case MODE_ETM:
		tct, err = x.cbcETM(data)
	case MODE_MTE:
		tct, err = x.cbcMTE(data)
	default:
		return nil, fmt.Errorf("no cipher mode(%v)", myself)
	}

	if err != nil {
		return nil, fmt.Errorf("TLSCipherText parse(%v): %v", myself, err)
	}

	// Compute MAC and compare
	content := tct.Fragment.(*GenericBlockCipher).Content
	givenMAC := tct.Fragment.(*GenericBlockCipher).Mac
	dataMac := seqNumToBytes(x.seqNum)
	dataMac = append(dataMac, TLSHeadPacket(tct.Header)...)
	dataMac = append(dataMac, content...)
	computedMAC, err := x.cipherSuite.MacMe(dataMac, x.keys.MAC)
	if err != nil {
		return nil, fmt.Errorf("MAC calculation(%v): %v", myself, err)
	}

	if !hmac.Equal(givenMAC, computedMAC) {
		return nil, fmt.Errorf("MAC mismatch(%v)", myself)
	}

	return tct, nil
}

// Turn 'data' into a TLSCipherText
// When cipherMode is MTE order is:
// TLSHEADER | IV | CipherBlock(DATA | MAC | PADDING | PADDING_LENGTH)
// If seqNum is 0 that means is (or should be) the 'Finished' message
func (x *xTLSCipherSpec) cbcMTE(data []byte) (*TLSCipherText, error) {

	var tct TLSCipherText
	var fragment GenericBlockCipher
	var suiteCtx suite.SuiteContext

	suiteCtx.Key = x.keys.Key
	suiteCtx.HKey = x.keys.MAC
	ivSz := x.cipherSuite.Info().IVSize
	if x.seqNum == 0 {
		suiteCtx.IV = x.keys.IV
		suiteCtx.Data = data[TLS_HEADER_SIZE:]
	} else {
		suiteCtx.IV = data[TLS_HEADER_SIZE : TLS_HEADER_SIZE+ivSz]
		suiteCtx.Data = data[TLS_HEADER_SIZE+ivSz:]
	}

	myName := systema.MyName()
	decoded, err := x.cipherSuite.CipherNot(&suiteCtx)
	if err != nil {
		return nil, fmt.Errorf("fail decipher(%v): %v", myName, err)
	}

	if len(decoded) < ivSz+HMAC_SIZE {
		return nil, fmt.Errorf("decoded too short(%v)", myName)
	}

	// TLS Header
	tct.Header = TLSHead(data[:TLS_HEADER_SIZE])
	fragment.IV = suiteCtx.IV
	if x.seqNum == 0 {
		fragment.Content = decoded[ivSz : len(decoded)-HMAC_SIZE]
		fragment.Mac = decoded[len(decoded)-HMAC_SIZE:]
	} else {
		return nil, fmt.Errorf("AGUANTALO")
	}

	// The TLS header used to calculate the MAC was the
	// 'original' (before encription + mac)
	tct.Header.Len = len(fragment.Content)
	tct.Fragment = &fragment
	return &tct, nil
}

func (x *xTLSCipherSpec) cbcETM(data []byte) (*TLSCipherText, error) {
	return nil, fmt.Errorf("not implemented yet 2")
}
