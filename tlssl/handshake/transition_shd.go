package handshake

import (
	"fmt"

	"github.com/julinox/funtls/tlssl"
)

func (x *xTransition) transitServerHelloDone() error {

	x.tCtx.Lg.Info("Transitioning from SERVERHELLODONE")
	// Send all packets
	x.ctx.SendCtxBuff(x.ctx.Order())

	// Read 'Expected()' client response packets
	// Wait for '_READ_TIMEOUT_' seconds then return error
	for {

		x.tCtx.Lg.Info("Waiting for client response...")
		x.tCtx.Lg.Debug("Expect TLS Records: ", x.ctx.PrintExpected())
		coms := x.ctx.GetComms()
		if coms == nil {
			return fmt.Errorf("nil net.Conn object")
		}

		//coms.SetDeadline(time.Now().Add(_READ_TIMEOUT_ * time.Second))
		//x.ctx.ComsDeadline(_READ_TIMEOUT_)
		buff := make([]byte, _BUFFER_SIZE_)
		n, err := coms.Read(buff)
		if err != nil {
			return fmt.Errorf("expected packets readerror: %v", err.Error())
		} else if n == 0 {
			return fmt.Errorf("expected packets readerror: nodata")
		}

		whoIsIt, err := tlssl.TLSRecordsDecode(buff[:n])
		if err != nil {
			return fmt.Errorf("decoding client records: %v", err.Error())
		}

		for i, who := range whoIsIt {
			switch who.Header.ContentType {
			case tlssl.ContentTypeChangeCipherSpec:
				x.tCtx.Lg.Debugf("Received %v",
					handshakeName(CHANGECIPHERSPEC))
				x.ctx.UnAppendExpected(CHANGECIPHERSPEC)
				if i >= len(whoIsIt)-1 {
					x.tCtx.Lg.Warn("No more packets after change cipher spec")
					break
				}

				x.tCtx.Lg.Debugf("Received %v(?)", handshakeName(FINISHED))
				x.ctx.SetBuffer(FINISHED, whoIsIt[i+1].Msg)
				x.ctx.UnAppendExpected(FINISHED)

			case tlssl.ContentTypeHandshake:
				x.isExpected(who)
			}
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

func (x *xTransition) isExpected(record *tlssl.TLSRecord) {

	switch record.HandShake.HandshakeType {
	case tlssl.HandshakeTypeCertificate:
		if x.ctx.Expected()&CERTIFICATE != 0 {
			x.tCtx.Lg.Debugf("Received %v(CLIENT)", handshakeName(CERTIFICATE))
			x.ctx.SetBuffer(CLIENTCERTIFICATE, record.Msg)
			x.ctx.UnAppendExpected(CERTIFICATE)
		}

	case tlssl.HandshakeTypeClientKeyExchange:
		if x.ctx.Expected()&CLIENTKEYEXCHANGE != 0 {
			x.tCtx.Lg.Debugf("Received %v", handshakeName(CLIENTKEYEXCHANGE))
			x.ctx.SetBuffer(CLIENTKEYEXCHANGE, record.Msg)
			x.ctx.UnAppendExpected(CLIENTKEYEXCHANGE)
		}

	case tlssl.HandshakeTypeCertificateVerify:
		if x.ctx.Expected()&CERTIFICATEVERIFY != 0 {
			x.tCtx.Lg.Debugf("Received %v", handshakeName(CERTIFICATEVERIFY))
			x.ctx.SetBuffer(CERTIFICATEVERIFY, record.Msg)
			x.ctx.UnAppendExpected(CERTIFICATEVERIFY)
		}

	default:
		if x.ctx.Expected()&CHANGECIPHERSPEC != 0 {
			x.tCtx.Lg.Warnf("Unexpected '%v' client message",
				record.HandShake.HandshakeType)
		}
	}
}
