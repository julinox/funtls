package interfaces

import (
	"github.com/sirupsen/logrus"
)

type Certificate interface {
	Name() string
	Handle()
	Packet() []byte
}

type xCertificate struct {
	lg *logrus.Logger
}

func NewIfcCertificate(lg *logrus.Logger) Certificate {

	var newCertificate xCertificate

	if lg == nil {
		return nil
	}

	newCertificate.lg = lg
	return &newCertificate
}

func (c *xCertificate) Name() string {
	return "Certificate"
}

func (c *xCertificate) Handle() {

	// Choose certifcate list to send
	// For that i need 2 extensions: ServerName and SignatureAlgorithms
	// Need the data sent by the client regarding these 2 extensions

}

func (c *xCertificate) Packet() []byte {
	return nil
}
