package handshake

import (
	"crypto/x509"
	"fmt"
	"tlesio/systema"
	"tlesio/tlssl"
	ex "tlesio/tlssl/extensions"
	"tlesio/tlssl/suites"
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

// Choose certifcate list to send. Extensions ServerName and
// SignatureAlgorithms are used to select one
// First certificate in the list is the chosen one
func (x *xCertificate) certificateServer() error {

	//var certificatesBuff []byte
	var certs []*x509.Certificate

	x.tCtx.Lg.Tracef("Running state: %v(SERVER)", x.Name())
	x.tCtx.Lg.Debugf("Running state: %v(SERVER)", x.Name())
	cs := x.tCtx.Modz.TLSSuite.GetSuite(x.ctx.GetCipherSuite())
	if cs == nil {
		return fmt.Errorf("%v: invalid cipher suite", x.Name())
	}

	helloMsg := x.ctx.GetMsgHello()
	dnsNames := getClientCnames(helloMsg.Extensions[0x0000])
	saAlgos := getClientSaAlgos(helloMsg.Extensions[0x000D])

	// Brute force. Why ???
	for _, cn := range dnsNames {
		for _, sa := range saAlgos {
			if cert := x.tCtx.Modz.Certs.GetByCriteria(sa, cn); cert != nil {
				certs = append(certs, cert)
				break
			}
		}
	}

	if len(certs) == 0 {
		return fmt.Errorf("%v: no certificate found", x.Name())
	}

	// Certs
	certificateBuff := packetCerts(certs)

	// Headers
	header := tlssl.TLSHeadsHandShakePacket(tlssl.HandshakeTypeCertificate,
		len(certificateBuff))

	x.ctx.SetBuffer(CERTIFICATE, append(header, certificateBuff...))
	x.ctx.AppendOrder(CERTIFICATE)

	if cs.Info().KeyExchange == suites.DHE {
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

func getClientCnames(data interface{}) []string {

	var dnsNames []string

	if data == nil {
		return nil
	}

	extData, ok := data.(*ex.ExtSNIData)
	if !ok {
		return nil
	}

	dnsNames = make([]string, 0)
	for _, name := range extData.Names {
		dnsNames = append(dnsNames, name.Name)
	}

	return dnsNames
}

func getClientSaAlgos(data interface{}) []uint16 {

	if data == nil {
		return nil
	}

	extData, ok := data.(*ex.ExtSignAlgoData)
	if !ok {
		return nil
	}

	return extData.Algos
}
