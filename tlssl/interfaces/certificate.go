package interfaces

import (
	ex "tlesio/tlssl/extensions"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type Certificate interface {
	Name() string
	Handle()
	Packet() []byte
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

func (c *xCertificate) Name() string {
	return "Certificate"
}

func (c *xCertificate) Handle() {

	// Choose certifcate list to send. Extensions ServerName and
	// SignatureAlgorithms are used to select one

}

func (c *xCertificate) Packet() []byte {
	return nil
}
