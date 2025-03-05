package tester

import (
	"fmt"
	"math"
	"net"
	"os"
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
}

func TestStageFinishedClient(t *testing.T) {

	var newCtx handshake.AllContexts

	lg := testLogger()
	//messages := []int{handshake.CHANGECIPHERSPEC}
	messages := []int{handshake.CHANGECIPHERSPEC, handshake.CLIENTKEYEXCHANGE,
		handshake.CERTIFICATE, handshake.CERTIFICATEVERIFY}
	//messages := []int{handshake.CHANGECIPHERSPEC, _HANDSHAKE_TIMEOUT_}
	newCtx.Hctx = testCtxHandshake(&testHandshakeCtxData{
		comms: &xFakeConn{msgs: messages},
		stage: handshake.STAGE_SERVERHELLODONE,
		expected: handshake.CLIENTKEYEXCHANGE | handshake.CHANGECIPHERSPEC |
			handshake.CERTIFICATE | handshake.CERTIFICATEVERIFY,
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

	if x.msgsCtr >= len(x.msgs) {
		fmt.Println("No more messages")
		return 0, nil
	}

	time.Sleep(350 * time.Millisecond)
	msg := x.msgs[x.msgsCtr]
	x.msgsCtr++
	switch msg {
	case handshake.CHANGECIPHERSPEC:
		return copia(b, changeCipherSpec), nil

	case handshake.CERTIFICATE:
		return copia(b, certificate), nil

	case handshake.CLIENTKEYEXCHANGE:
		return copia(b, clientKeyExchange), nil

	case handshake.CERTIFICATEVERIFY:
		return copia(b, certificateVerify), nil

	case _HANDSHAKE_TIMEOUT_:
		time.Sleep(time.Duration(x.deadlineSec) * time.Second)
		return 0, os.ErrDeadlineExceeded
	}

	return 0, nil
}

func (x *xFakeConn) SetDeadline(t time.Time) error {
	x.deadlineSec = int(math.Ceil(time.Until(t).Seconds()))
	return nil
}

func changeCipherSpec() []byte {
	return []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
}

func certificate() []byte {

	return []byte{
		0x16, 0x03, 0x03, 0x00, 0x1D, 0x0B, 0x00, 0x00, 0x19, 0x00, 0x00, 0x16, 0x00, 0x00, 0x13, 0x30,
	}
}

func clientKeyExchange() []byte {

	// PreMasterSecret 48 bytes
	return []byte{
		0x16, 0x03, 0x03, 0x00, 0xA4, 0x10, 0x00, 0x00, 0xA0, 0x03, 0x03, 0x5B, 0x57, 0x76, 0xA0, 0x98,
		0x72, 0x6C, 0x8B, 0x6C, 0xC0, 0x26, 0x51, 0x84, 0x5B, 0xE3, 0x1D, 0xF0, 0x8B, 0x7F, 0x33, 0x60,
		0x65, 0xE3, 0x48, 0x63, 0xAB, 0xBC, 0xA9, 0xF4, 0x99, 0x73, 0x8C, 0xE4, 0x41, 0x9A, 0xF1, 0x52,
		0xDC, 0x61, 0x04, 0x1B, 0xB9, 0x7A, 0x70, 0x63, 0x82, 0x29, 0x4F, 0xB7, 0x9D, 0x64, 0x0A, 0x23,
		0x6D, 0x0E, 0x10, 0xB2, 0xA7, 0xD5, 0x55, 0x32, 0x1C, 0xE5, 0x9E, 0x06, 0x0A, 0x8F, 0xF3, 0x3C,
		0x33, 0x33, 0x7E, 0x99, 0x44, 0xF6, 0x59, 0x2F, 0x6E, 0xDC, 0xA1, 0x56, 0x24, 0x1F, 0x1F, 0x93,
		0xA4, 0x28, 0x97, 0x2D, 0xA5, 0xB3, 0x74, 0x74, 0x70, 0xC3, 0xB2, 0xB7, 0x56, 0x44, 0x69, 0xE6,
	}
}

func certificateVerify() []byte {

	return []byte{
		0x16, 0x03, 0x03, 0x00, 0x1D, 0x0F, 0x00, 0x00, 0x19, 0x01, 0x02, 0x16, 0x00, 0x00, 0x13, 0x30,
	}
}

func copia(buff []byte, fn func() []byte) int {

	pkt := fn()
	copy(buff, pkt)
	return len(pkt)
}
