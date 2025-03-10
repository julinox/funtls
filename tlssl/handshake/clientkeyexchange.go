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

	x.tCtx.Lg.Tracef("Running state: %v", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v", x.Name())
	kBuff := x.ctx.GetBuffer(CLIENTKEYEXCHANGE)
	if kBuff == nil {
		return fmt.Errorf("nil ClientKeyExchange buffer(%v)", x.Name())
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

	// Parse the coded pre master secret from the client key exchange message
	aux := tlssl.TLS_HEADER_SIZE + tlssl.TLS_HANDSHAKE_SIZE
	if len(kBuff[aux:]) < 2 {
		return fmt.Errorf("PreMasterSecreto no content(%v)", x.Name())
	}

	kBuff = kBuff[aux:]
	pmsLen := uint16(kBuff[0])<<8 | uint16(kBuff[1])
	if int(pmsLen) != len(kBuff[2:]) {
		return fmt.Errorf("PreMasterSecreto len unmatched(%v)", x.Name())
	}

	// Decode the pre master secret
	pmsCoded := kBuff[2:]
	x.tCtx.Lg.Tracef("Received PreMasterSecreto: %x", pmsCoded)
	pms, err := x.preMasterSecret(pmsCoded)
	if err != nil {
		return err
	}

	// Calculate the session keys
	x.tCtx.Lg.Tracef("Decrypted PreMasterSecreto: %x", pms)
	sessionKeys, err := x.genSessionKeys(pms)
	if err != nil {
		return fmt.Errorf("sesh keys generate(%v): %v", x.Name(), err.Error())
	}

	x.ctx.SetKeys(sessionKeys)
	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEVERIFY
	} else {
		x.nextState = CHANGECIPHERSPEC
	}

	return nil
}

// Calculate the pre master secret
func (x *xClientKeyExchange) preMasterSecret(cPms []byte) ([]byte, error) {

	cs := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return nil, fmt.Errorf("cipher suite get err(%v)", x.Name())
	}

	switch cs.Info().KeyExchange {
	case suite.RSA:
		return x.preMasterSecretRSA(cPms)

	case suite.DHE:
		return x.preMasterSecretDHE(cPms)
	}

	return nil, fmt.Errorf("key exchange not implemented yet(%v)", x.Name())
}

func (x *xClientKeyExchange) preMasterSecretRSA(cPms []byte) ([]byte, error) {

	ctxCert := x.ctx.GetCert()
	if ctxCert == nil {
		return nil, fmt.Errorf("handshakectx nil certificate(%v)", x.Name())
	}

	privateKey := x.tCtx.Modz.Certs.GetCertKey(ctxCert)
	if privateKey == nil {
		return nil, fmt.Errorf("cert's private key not found(%v)", x.Name())
	}

	pms, err := decodeRSA(cPms, privateKey)
	if err != nil {
		return nil, fmt.Errorf("%v(%v)", err.Error(), x.Name())
	}

	if len(pms) != _PMS_SIZE_ {
		return nil, fmt.Errorf("invalid pre master secret len(%v)", x.Name())
	}

	return pms, nil
}

func (x *xClientKeyExchange) preMasterSecretDHE(buff []byte) ([]byte, error) {
	return nil, fmt.Errorf("key exchange DHE not implemented yet")
}

func decodeRSA(data []byte, key crypto.PrivateKey) ([]byte, error) {

	// Decode the data
	rsaPkey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key")
	}

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPkey, data)
	if err != nil {
		return nil, fmt.Errorf("decryption error: %v", err)
	}

	return decrypted, nil
}

func (x *xClientKeyExchange) genSessionKeys(pms []byte) (*SessionKeys, error) {

	var newKeys SessionKeys

	cs := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return nil, fmt.Errorf("cipher suite get err(%v)", x.Name())
	}

	// Generate the master secret
	//ms := NewKeymaker()
	return &newKeys, nil
}
