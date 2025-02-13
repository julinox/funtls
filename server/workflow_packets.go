package server

import (
	"fmt"
	"tlesio/systema"
	ifs "tlesio/tlssl/interfaces"
	cbf "tlesio/tlssl/interfaces/cryptobuff"
	mx "tlesio/tlssl/modulos"
)

func (wf *wkf) pktServerHelo(cMsg *ifs.MsgHelloCli) error {

	var outputBuff []byte

	sMsg, err := wf.ssl.ifs.ServerHelo.Handle(cMsg)
	if err != nil {
		return err
	}

	// Server hello payload
	sHelloBuff := wf.ssl.ifs.ServerHelo.Packet(sMsg)

	// Extensions payload
	extsBuff := wf.ssl.ifs.ServerHelo.PacketExtensions(cMsg)

	// Handshake header
	hsHeaderBuff := wf.ssl.ifs.TLSHead.HandShakePacket(&ifs.TLSHandshake{
		HandshakeType: ifs.HandshakeTypeServerHelo,
		Len:           len(sHelloBuff) + len(extsBuff)})

	// Concatenate all buffers
	outputBuff = append(outputBuff, hsHeaderBuff...)
	outputBuff = append(outputBuff, sHelloBuff...)
	outputBuff = append(outputBuff, extsBuff...)

	// Save server hello parameters
	wf.cryptoBuff.Set(cbf.SERVER_HELLO, outputBuff)
	wf.cryptoBuff.SetCipherSuite(sMsg.CipherSuite)
	wf.ssl.lg.Debugf("Suite chosen: %v(%v)",
		mx.CipherSuiteNames[sMsg.CipherSuite], sMsg.CipherSuite)
	return nil
}

// Build Certificate packet message and store it
func (wf *wkf) pktCertificate(cMsg *ifs.MsgHelloCli) error {

	var outputBuff []byte

	certs := wf.ssl.ifs.Certificake.Handle(cMsg)
	if certs == nil {
		return fmt.Errorf("certificate not found")
	}

	// Save chosen certificate
	wf.cryptoBuff.SetCert(certs[0])
	wf.ssl.lg.Debugf("Certificate found: %s", certs[0].Subject.CommonName)
	certsPartialBuff := wf.ssl.ifs.Certificake.Packet(certs)

	// Add total certificates length
	certsBuff := systema.Uint24(len(certsPartialBuff))
	certsBuff = append(certsBuff, certsPartialBuff...)

	// Handshake header
	hsHeaderBuff := wf.ssl.ifs.TLSHead.HandShakePacket(&ifs.TLSHandshake{
		HandshakeType: ifs.HandshakeTypeCertificate,
		Len:           len(certsBuff),
	})

	// Concatenate all buffers
	outputBuff = append(outputBuff, hsHeaderBuff...)
	outputBuff = append(outputBuff, certsBuff...)
	wf.cryptoBuff.Set(cbf.CERTIFICATE, outputBuff)
	return nil
}

func (wf *wkf) pktServerHeloDone() error {

	// Handshake header
	hsHeaderBuff := wf.ssl.ifs.TLSHead.HandShakePacket(&ifs.TLSHandshake{
		HandshakeType: ifs.HandshakeTypeServerHeloDone,
		Len:           0,
	})

	// Concatenate all buffers
	wf.cryptoBuff.Set(cbf.SERVER_HELLO_DONE, hsHeaderBuff)
	return nil
}
