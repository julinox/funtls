package tlssl

import (
	"fmt"
	"tlesio/tlssl/suite"
)

func (x *xTLSCipherSpec) cbc(data []byte) (*TLSCipherText, error) {

	switch x.cipherMode {
	case suite.ETM:
		return nil, fmt.Errorf("no ETM yet")

	case suite.MTE:
		return x.cbcMTE(data)
	}

	return nil, fmt.Errorf("no specific mode to cipher")
}

// AESCBC^-1(CiphertText) = Plaintext || HMAC
func (x *xTLSCipherSpec) cbcMTE(data []byte) (*TLSCipherText, error) {

	if x.seqNum == 0 {
		return x.cbcFinished(data)
	}

	fmt.Println("ENCONDE NON FINISHED")
	return nil, nil
}

func (x *xTLSCipherSpec) cbcFinished(data []byte) (*TLSCipherText, error) {

	// IV(Fake) | Finished | MAC | Padding | PaddingLen

	ctx := &suite.SuiteContext{
		Key:  x.keys.Key,
		IV:   x.keys.IV,
		Data: data,
	}

	decoded, err := x.cipherSuite.CipherNot(ctx)
	if err != nil {
		return nil, fmt.Errorf("CipherNot decode err: %v", err)
	}

	ivSz := x.cipherSuite.Info().IVSize
	//if len(decoded) <
	fmt.Printf("DESCARTA IV: %v\n", x.cipherSuite.Info().IVSize)
	fmt.Printf("DECODED: %x\n", decoded)
	return nil, nil
}
