package interfaces

import (
	"encoding/binary"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type MsgCertificate struct {
	Length uint32
	Cert   []byte
}

type Certificate interface {
	Name() string
	Handle([]byte) ([]*MsgCertificate, error)
	Packet([]*MsgCertificate) []byte
}

type xCert struct {
	lg   *logrus.Logger
	mods mx.TLSModulo
}

func NewCertificate(lg *logrus.Logger, mods mx.TLSModulo) Certificate {

	if lg == nil || mods == nil {
		return nil
	}

	return &xCert{
		lg:   lg,
		mods: mods,
	}
}

func (crt *xCert) Name() string {
	return "Certificate"
}

func (crt *xCert) Handle(msg []byte) ([]*MsgCertificate, error) {

	// No hay handle
	return nil, nil
}

func (crt *xCert) Packet(msg []*MsgCertificate) []byte {

	var newBuff []byte

	for _, cert := range msg {
		aux := make([]byte, 4)
		binary.BigEndian.PutUint32(aux, cert.Length)
		newBuff = append(newBuff, aux[1:4]...)
		newBuff = append(newBuff, cert.Cert...)
	}

	return newBuff
}
