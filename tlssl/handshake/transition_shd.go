package handshake

import (
	"fmt"
	"time"
	"tlesio/tlssl"
)

func (x *xTransition) transitServerHelloDone() error {

	x.tCtx.Lg.Info("Transitioning from SERVERHELLODONE")
	// Send all packets
	x.ctx.Send(x.ctx.Order())
	x.tCtx.Lg.Debug("Sent packets: ", x.ctx.PrintOrder())

	// Read 'Expected()' client response packets
	// Wait for '_READ_TIMEOUT_' seconds then return error
	for {

		x.tCtx.Lg.Info("Waiting for client response...")
		fmt.Println("EXPECTED: ", x.ctx.PrintExpected())
		coms := x.ctx.GetComms()
		if coms == nil {
			return fmt.Errorf("nil net.Conn object")
		}

		coms.SetDeadline(time.Now().Add(_READ_TIMEOUT_ * time.Second))
		buff := make([]byte, _BUFFER_SIZE_)
		n, err := coms.Read(buff)
		if err != nil {
			return fmt.Errorf("expected packets readerror: %v", err.Error())
		} else if n == 0 {
			return fmt.Errorf("expected packets readerror: nodata")
		}

		who := tlssl.TLSHead(buff[:tlssl.TLS_HEADER_SIZE])
		err = tlssl.TLSHeadCheck(who)
		if err != nil {
			return fmt.Errorf("no TLS response from client: %v", err.Error())
		}

		switch who.ContentType {
		case tlssl.ContentTypeChangeCipherSpec:
			x.isExpected(CHANGECIPHERSPEC, "ChangeCipherSpec")

		case tlssl.ContentTypeHandshake:
			x.parseClientHandshakePacket(buff[:n])
		}

		if x.ctx.Expected() == 0 {
			break
		}
	}

	if x.tCtx.OptClientAuth {
		x.nextState = CERTIFICATE
	} else {
		x.nextState = CLIENTKEYEXCHANGE
	}

	x.ctx.SetTransitionStage(STAGE_FINISHED_CLIENT)
	return nil
}

func (x *xTransition) parseClientHandshakePacket(buff []byte) {

	hs := tlssl.TLSHeadHandShake(buff[tlssl.TLS_HEADER_SIZE:])
	if hs == nil {
		x.tCtx.Lg.Warn("Invalid handshake packet")
		return
	}

	switch hs.HandshakeType {
	case tlssl.HandshakeTypeCertificate:
		if x.isExpected(CERTIFICATE, "Certificate") {
			x.tCtx.Lg.Debug("Save client certificate")
		}

	case tlssl.HandshakeTypeClientKeyExchange:
		if x.isExpected(CLIENTKEYEXCHANGE, "ClientKeyExchange") {
			x.tCtx.Lg.Debug("Save client key Exchange")
		}

	case tlssl.HandshakeTypeCertificateVerify:
		if x.isExpected(CERTIFICATEVERIFY, "CertificateVerify") {
			x.tCtx.Lg.Debug("Save client certificate verify")
		}

	case tlssl.HandshakeTypeFinished:
		if x.isExpected(FINISHED, "Finished") {
			x.tCtx.Lg.Debug("Save client finished")
		}

	default:
		x.tCtx.Lg.Warnf("Unexpected '%v' client message", hs.HandshakeType)
	}

}

func (x *xTransition) isExpected(hsM int, name string) bool {

	if x.ctx.Expected()&hsM == 0 {
		x.tCtx.Lg.Warnf("Unexpected '%v' client message", name)
		return false
	}

	x.tCtx.Lg.Debugf("Received '%v'", name)
	x.ctx.UnAppendExpected(hsM)
	return true
}
