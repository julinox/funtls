package interfaces

import (
	"crypto/x509"
	"tlesio/systema"
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type Certificate interface {
	Name() string
	Packet([]*x509.Certificate) []byte
	Handle(*MsgHelloCli) []*x509.Certificate
}

type xCertificate struct {
	exts *ex.Extensions
	lg   *logrus.Logger
	mods *mx.ModuloZ
}

func NewIfcCertificate(params *IfaceParams) Certificate {

	var newCertificate xCertificate

	if params.Lg == nil || params.Ex == nil {
		return nil
	}

	newCertificate.lg = params.Lg
	newCertificate.exts = params.Ex
	newCertificate.mods = params.Mx
	return &newCertificate
}

func (x *xCertificate) Name() string {
	return "Certificate"
}

func (x *xCertificate) Handle(cMsg *MsgHelloCli) []*x509.Certificate {

	// Choose certifcate list to send. Extensions ServerName and
	// SignatureAlgorithms are used to select one

	var certs []*x509.Certificate

	dnsNames := x.getClientCnames(cMsg.Extensions[0x0000])
	saAlgos := x.getClientSaAlgos(cMsg.Extensions[0x000D])

	// Brute force. Why ???
	for _, cn := range dnsNames {
		for _, sa := range saAlgos {
			if cert := x.mods.Certs.GetByCriteria(sa, cn); cert != nil {
				certs = append(certs, cert)
				return certs
			}
		}
	}

	return nil
}

func (x *xCertificate) Packet(certs []*x509.Certificate) []byte {

	var certsBuffer []byte

	certsBuffer = make([]byte, 0)
	for _, cert := range certs {
		auxBuffer := systema.Uint24(len(cert.Raw))
		certsBuffer = append(certsBuffer, auxBuffer...)
		certsBuffer = append(certsBuffer, cert.Raw...)
	}

	return certsBuffer
}

func (x xCertificate) getClientCnames(data interface{}) []string {

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

func (x xCertificate) getClientSaAlgos(data interface{}) []uint16 {

	if data == nil {
		return nil
	}

	extData, ok := data.(*ex.ExtSignAlgoData)
	if !ok {
		return nil
	}

	return extData.Algos
}
