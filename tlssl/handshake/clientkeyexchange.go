package handshake

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"tlesio/tlssl"
	"tlesio/tlssl/suite"
)

const _PMS_SIZE_ = 48

type xClientKeyExchange struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewClientKeyExchange(actx *AllContexts) ClientKeyExchange {

	var newX xClientKeyExchange

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xClientKeyExchange) Name() string {
	return "_ClientKeyExchange_"
}

func (x *xClientKeyExchange) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xClientKeyExchange) Handle() error {

	var err error

	kBuff := x.ctx.GetBuffer(CLIENTKEYEXCHANGE)
	if kBuff == nil {
		return fmt.Errorf("nil ClientKeyExchange buffer")
	}

	// Remove TLS Header
	hh := tlssl.TLSHeadHandShake(kBuff[tlssl.TLS_HEADER_SIZE:])
	if hh == nil {
		return fmt.Errorf("nil TLSHeaderHandShake object(%v)", x.Name())
	}

	if hh.HandshakeType != tlssl.HandshakeTypeClientKeyExchange {
		return fmt.Errorf("invalid HandshakeType(%v)", x.Name())
	}

	if hh.Len != len(kBuff[tlssl.TLS_HEADER_SIZE+tlssl.TLS_HANDSHAKE_SIZE:]) {
		return fmt.Errorf("invalid HandshakeLen(%v)", x.Name())
	}

	aux := tlssl.TLS_HEADER_SIZE + tlssl.TLS_HANDSHAKE_SIZE
	pms, err := x.parsePMS(kBuff[aux:])
	if err != nil {
		return err
	}

	x.tCtx.Lg.Tracef("Received pre master secret: %x", pms)
	err = x.pmsMe(pms)
	if err != nil {
		return err
	}

	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEVERIFY
	} else {
		x.nextState = CHANGECIPHERSPEC
	}

	fmt.Println("I AM: ", x.Name())
	return nil
}

// Parse the pre master secret from the client key exchange message
func (x xClientKeyExchange) parsePMS(buffer []byte) ([]byte, error) {

	if len(buffer) < 2 {
		return nil, fmt.Errorf("buffer too small")
	}

	pmsLen := uint16(buffer[0])<<8 | uint16(buffer[1])
	if int(pmsLen) != len(buffer[2:]) {
		return nil, fmt.Errorf("pre master secret len does not match content")
	}

	return buffer[2:], nil
}

// Calculate the pre master secret
func (x *xClientKeyExchange) pmsMe(buff []byte) error {

	cs := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return fmt.Errorf("cipher suite get err(%v)", x.Name())
	}

	switch cs.Info().KeyExchange {
	case suite.RSA:
		return x.pmsRSA(buff)

	case suite.DHE:
		return x.pmsDHE(buff)
	}

	return fmt.Errorf("key exchange not implemented yet(%v)", x.Name())
}

func (x *xClientKeyExchange) pmsRSA(buff []byte) error {

	ctxCert := x.ctx.GetCert()
	if ctxCert == nil {
		return fmt.Errorf("handshakectx nil certificate(%v)", x.Name())
	}

	privateKey := x.tCtx.Modz.Certs.GetCertKey(ctxCert)
	if privateKey == nil {
		return fmt.Errorf("cert's private key not found(%v)", x.Name())
	}

	pms, err := decodeThisRSA(buff, privateKey)
	if err != nil {
		return fmt.Errorf("%v(%v)", err.Error(), x.Name())
	}

	if len(pms) != _PMS_SIZE_ {
		return fmt.Errorf("invalid pre master secret len(%v)", x.Name())
	}

	x.tCtx.Lg.Tracef("Decrypted pre master secret: %x", pms)
	return nil
}

func (x *xClientKeyExchange) pmsDHE(buff []byte) error {
	return fmt.Errorf("key exchange DHE not implemented yet")
}

func decodeThisRSA(data []byte, pkey crypto.PrivateKey) ([]byte, error) {

	// Decode the data
	rsaPkey, ok := pkey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key")
	}

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPkey, data)
	if err != nil {
		return nil, fmt.Errorf("decryption error: %v", err)
	}

	return decrypted, nil
}
