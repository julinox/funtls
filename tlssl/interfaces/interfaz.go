package interfaces

import (
	"tlesio/systema"
	mx "tlesio/tlssl/modulos"

	"github.com/sirupsen/logrus"
)

type Interfaces struct {
	TLSHead    Header
	CliHelo    CliHello
	ServerHelo ServerHello
	//Certificake Certificate
}

func InitInterfaces(lg *logrus.Logger, mods *mx.ModuloZ) (*Interfaces, error) {

	var newHsIf Interfaces

	if lg == nil || mods == nil {
		return nil, systema.ErrNilParams
	}

	newHsIf.TLSHead = NewHeader()
	lg.Info("Interface loaded: ", newHsIf.TLSHead.Name())
	newHsIf.CliHelo = NewCliHello(lg, mods)
	lg.Info("Interface loaded: ", newHsIf.CliHelo.Name())
	newHsIf.ServerHelo = NewServerHello(lg, mods)
	lg.Info("Interface loaded: ", newHsIf.ServerHelo.Name())
	//newHsIf.Certificake = NewCertificate(lg, mods)
	//lg.Info("Interface loaded: ", newHsIf.Certificake.Name())
	return &newHsIf, nil
}

/*

// 'Packetize' a bunch of certificates
func (x *_xModCerts) Packet(msg []*MsgCertificate) []byte {

	var newBuff []byte

	for _, cert := range msg {
		aux := make([]byte, 4)
		binary.BigEndian.PutUint32(aux, cert.Length)
		newBuff = append(newBuff, aux[1:4]...)
		newBuff = append(newBuff, cert.Cert...)
	}

	return newBuff
}
*/
