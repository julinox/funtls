package handshake

import (
	"fmt"
	"tlesio/tlssl"
)

func (x *xTransition) transitServerHelloDone() error {

	x.tCtx.Lg.Info("Transitioning from SERVERHELLODONE")
	// Send all packets
	x.ctx.Send(x.ctx.Order())
	x.tCtx.Lg.Debug("Sent packets: ", x.ctx.PrintOrder())

	// Read client response packets
	for {

		x.tCtx.Lg.Info("Waiting for client response...")
		coms := x.ctx.GetComms()
		if coms == nil {
			return fmt.Errorf("nil net.Conn object")
		}

		buff := make([]byte, _BUFFER_SIZE_)
		n, err := coms.Read(buff)
		if err != nil || n == 0 {
			return fmt.Errorf("expected packets readerror/nodata")
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
			x.parseClientHandshakePacket(buff[tlssl.TLS_HEADER_SIZE:])
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

	hs := tlssl.TLSHeadHandShake(buff)
	if hs == nil {
		x.tCtx.Lg.Warn("Invalid handshake packet")
		return
	}

	switch hs.HandshakeType {
	case tlssl.HandshakeTypeClientKeyExchange:
		x.isExpected(CLIENTKEYEXCHANGE, "ClientKeyExchange")

	default:
		x.tCtx.Lg.Warnf("Unexpected '%v' client message", hs.HandshakeType)
	}

}

func (x *xTransition) isExpected(hsM int, name string) {

	if x.ctx.Expected()&hsM == 0 {
		x.tCtx.Lg.Warnf("Unexpected '%v' client message", name)
		return
	}

	x.tCtx.Lg.Debugf("Received '%v'", name)
	x.ctx.UnAppendExpected(hsM)
}
