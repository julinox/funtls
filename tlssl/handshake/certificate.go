package handshake

import (
	"crypto/x509"
	"fmt"

	"github.com/julinox/funtls/systema"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/names"
)

type xCertificate struct {
	stateBasicInfo
	tCtx *tlssl.TLSContext
}

func NewCertificate(actx *AllContexts) Certificate {

	var newX xCertificate

	if actx == nil || actx.Tctx == nil || actx.Hctx == nil {
		return nil
	}

	newX.ctx = actx.Hctx
	newX.tCtx = actx.Tctx
	return &newX
}

func (x *xCertificate) Name() string {
	return "_Certificate_"
}

func (x *xCertificate) Next() (int, error) {
	return x.nextState, x.Handle()
}

func (x *xCertificate) Handle() error {

	switch x.ctx.GetTransitionStage() {
	case STAGE_SERVERHELLODONE:
		return x.certificateServer()

	case STAGE_FINISHED_CLIENT:
		return x.certificateClient()

	default:
		return fmt.Errorf("%v: invalid transition stage", x.Name())
	}
}

// The first certificate in the list is the end-entity certificate used in the
// handshake. This is followed by any intermediate certificates that form the
// chain. Typically, the root certificate is omitted because the client should
// already have it, but can be included if the client does not have it, which
// is not recommended for the client to do so.
func (x *xCertificate) certificateServer() error {

	x.tCtx.Lg.Tracef("Running state: %v(SERVER)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(SERVER)", x.Name())
	cs := x.tCtx.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return fmt.Errorf("%v: invalid cipher suite", x.Name())
	}

	return fmt.Errorf("ESTO ESTA MAL certificate.go linea 66")
	certChain := x.tCtx.CertPKI.Get(x.ctx.GetCertFingerprint())
	if len(certChain) == 0 {
		return fmt.Errorf("%v: no certificate chain", x.Name())
	}

	certificateBuff := packetCerts(certChain)
	header := tlssl.TLSHeadsHandShakePacket(tlssl.HandshakeTypeCertificate,
		len(certificateBuff))
	x.ctx.SetBuffer(CERTIFICATE, append(header, certificateBuff...))
	x.ctx.AppendOrder(CERTIFICATE)
	if cs.Info().KeyExchange == names.KX_DHE ||
		cs.Info().KeyExchange == names.KX_ECDHE {
		x.nextState = SERVERKEYEXCHANGE

	} else if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATEREQUEST

	} else {
		x.nextState = SERVERHELLODONE
	}

	return nil
}

func (x *xCertificate) certificateClient() error {

	x.tCtx.Lg.Tracef("Running state: %v(CLIENT)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(CLIENT)", x.Name())
	x.nextState = CLIENTKEYEXCHANGE
	return nil
}

// Pack all certificates.
func packetCerts(certs []*x509.Certificate) []byte {

	var finalBuff, certsBuffer []byte

	certsBuffer = make([]byte, 0)
	for _, cert := range certs {
		auxBuffer := systema.Uint24(len(cert.Raw))
		certsBuffer = append(certsBuffer, auxBuffer...)
		certsBuffer = append(certsBuffer, cert.Raw...)
	}

	// Add length of all certificates
	finalBuff = systema.Uint24(len(certsBuffer))
	return append(finalBuff, certsBuffer...)
}
