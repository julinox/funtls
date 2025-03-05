package tester

import (
	"math"
	"net"
	"testing"
	"time"
	"tlesio/tlssl"
	"tlesio/tlssl/handshake"
)

var _HANDSHAKE_TIMEOUT_ = 3

type xFakeConn struct {
	net.Conn
	deadlineSec int
	msgsCtr     int
	msgs        []int
	modo        int
	sleepp      int
}

func TestStageFinishedClient(t *testing.T) {

	var newCtx handshake.AllContexts

	lg := testLogger()
	newCtx.Hctx = testCtxHandshake(&testHandshakeCtxData{
		comms: &xFakeConn{msgs: msgsToSend()},
		//comms:    &xFakeConn{msgs: msgsToSend(), modo: 1, sleepp: 400},
		stage:    handshake.STAGE_SERVERHELLODONE,
		expected: handshake.CLIENTKEYEXCHANGE | handshake.CHANGECIPHERSPEC,
	})

	if newCtx.Hctx == nil {
		t.Errorf("Error: %v", "nil handshake context")
		return
	}

	newCtx.Tctx = &tlssl.TLSContext{
		Lg: lg,
	}

	transit := handshake.NewTransition(&newCtx)
	lg.Info("Starting test")
	if err := transit.Handle(); err != nil {
		t.Errorf("Error: %v", err)
	}
}

func (x *xFakeConn) Read(b []byte) (int, error) {

	var all []byte

	for _, m := range x.msgs[x.msgsCtr:] {
		if x.sleepp > 0 {
			time.Sleep(time.Duration(x.sleepp) * time.Millisecond)
		}

		switch m {
		case handshake.CHANGECIPHERSPEC:
			all = append(all, changeCipherSpec()...)

		case handshake.CERTIFICATE:
			all = append(all, certificate()...)

		case handshake.CLIENTKEYEXCHANGE:
			all = append(all, clientKeyExchange()...)

		case handshake.CERTIFICATEVERIFY:
			all = append(all, certificateVerify()...)

		case handshake.FINISHED:
			all = append(all, finished()...)
		}

		if x.modo == 1 {
			x.msgsCtr++
			break
		}
	}

	copy(b, all)
	return len(all), nil
}

func (x *xFakeConn) SetDeadline(t time.Time) error {
	x.deadlineSec = int(math.Ceil(time.Until(t).Seconds()))
	return nil
}

func msgsToSend() []int {

	return []int{
		handshake.CERTIFICATE,
		handshake.CLIENTKEYEXCHANGE,
		handshake.FINISHED,
		handshake.CERTIFICATEVERIFY,
		handshake.CHANGECIPHERSPEC,
	}
}

func certificate() []byte {
	return []byte{
		// Content Type (Handshake)
		0x16,
		// Version (TLS 1.2)
		0x03, 0x03,
		// Length (1 byte Handshake Type + 3 bytes Handshake Length + 32 bytes Certificado)
		0x00, 0x24,
		// Handshake Type (Certificate)
		0x0B,
		// Handshake Length (32 bytes)
		0x00, 0x00, 0x20,
		// Certificado (32 bytes, ejemplo de valores)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	}
}

func changeCipherSpec() []byte {
	return []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
}

func clientKeyExchange() []byte {

	// PreMasterSecret 48 bytes
	return []byte{
		// Content Type (Handshake)
		0x16,
		// Version (TLS 1.2)
		0x03, 0x03,
		// Length (1 byte Handshake Type + 3 bytes Handshake Length + 24 bytes PreMasterSecret)
		0x00, 0x1C,
		// Handshake Type (ClientKeyExchange)
		0x10,
		// Handshake Length (24 bytes)
		0x00, 0x00, 0x18,
		// PreMasterSecret (24 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	}
}
func certificateVerify() []byte {

	return []byte{
		// Content Type (Handshake)
		0x16,
		// Version (TLS 1.2)
		0x03, 0x03,
		// Length (1 byte Handshake Type + 3 bytes Handshake Length + 16 bytes Firma)
		0x00, 0x14,
		// Handshake Type (CertificateVerify)
		0x0F,
		// Handshake Length (16 bytes)
		0x00, 0x00, 0x10,
		// Firma (16 bytes, ejemplo de valores)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
}

func finished() []byte {

	return []byte{
		// Content Type (Handshake)
		0x16,
		// Version (TLS 1.2)
		0x03, 0x03,
		// Length (1 byte Handshake Type + 3 bytes Handshake Length + 12 bytes Hash)
		0x00, 0x10,
		// Handshake Type (Finished)
		0x14,
		// Handshake Length (12 bytes)
		0x00, 0x00, 0x0C,
		// Hash (12 bytes, ejemplo de valores)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C,
	}
}

func copia(buff []byte, fn func() []byte) int {

	pkt := fn()
	copy(buff, pkt)
	return len(pkt)
}
