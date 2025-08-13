package connsec

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/cipherspec"
	"github.com/julinox/funtls/tlssl/names"
	"github.com/sirupsen/logrus"
)

const _MaxTLSRecordSize_ = 16384

var _CloseNotify_ = []byte{0x01, 0x00}

type TLSConn struct {
	RawConn   net.Conn
	SpecRead  cipherspec.CipherSpec
	SpecWrite cipherspec.CipherSpec
	Lg        *logrus.Logger
	DebugMode bool //ignore encript/decript errors
}

// bytes.Buffer behaves like a stream buffer (i.e mantains an internal index
// and do the "unbuffer" when needed)
type xTLSConn struct {
	debugMode  bool
	eofRead    bool
	eofWrite   bool
	peerClose  bool
	rawConn    net.Conn
	readRawBuf []byte
	readBuf    bytes.Buffer
	lg         *logrus.Logger
	specRead   cipherspec.CipherSpec
	specWrite  cipherspec.CipherSpec
}

func NewTLSConn(tc *TLSConn) (net.Conn, error) {

	if tc == nil {
		return nil, fmt.Errorf("nil TLSConn parameter")
	}

	if tc.DebugMode && tc.Lg == nil {
		return nil, fmt.Errorf("cannot use DebugMode without a logger")
	}

	return &xTLSConn{
		rawConn:   tc.RawConn,
		specRead:  tc.SpecRead,
		specWrite: tc.SpecWrite,
		debugMode: tc.DebugMode,
		lg:        tc.Lg,
	}, nil
}

// Any alert received will be ignored, but the connection will be closed
func (x *xTLSConn) Read(p []byte) (int, error) {

	if len(p) == 0 {
		return 0, nil
	}

	for {
		if x.readBuf.Len() > 0 {
			break
		}

		if x.peerClose {
			x.Close()
		}

		if x.eofRead {
			return 0, io.EOF
		}

		tmp := make([]byte, 4096)
		n, err := x.rawConn.Read(tmp)
		if err != nil {
			if err == io.EOF {
				x.eofRead = true
			}

			if n <= 0 {
				return 0, err
			}
		}

		x.readRawBuf = append(x.readRawBuf, tmp[:n]...)
		for {
			if len(x.readRawBuf) < tlssl.TLS_HEADER_SIZE {
				break
			}

			pktSz := int(x.readRawBuf[3])<<8 | int(x.readRawBuf[4])
			if pktSz > _MaxTLSRecordSize_ {
				return 0, fmt.Errorf("invalid record size")
			}

			if len(x.readRawBuf) < pktSz+tlssl.TLS_HEADER_SIZE {
				break
			}

			record := x.readRawBuf[:pktSz+tlssl.TLS_HEADER_SIZE]
			if record[0] == byte(tlssl.ContentTypeAlert) {
				x.handleAlert(record)
				break
			}

			plainText, err := x.specRead.DecryptRec(record)
			if err != nil {
				x.lg.Error("Error decrypting TLS record: ", err)
				if !x.debugMode {
					return 0, err
				}

				x.lg.Debugf("RawRead: %x",
					x.readRawBuf[:pktSz+tlssl.TLS_HEADER_SIZE])
			}

			x.readRawBuf = x.readRawBuf[pktSz+tlssl.TLS_HEADER_SIZE:]
			if plainText != nil {
				x.readBuf.Write(plainText)
			}
		}
	}

	return x.readBuf.Read(p)
}

func (x *xTLSConn) Write(p []byte) (int, error) {

	if len(p) == 0 {
		return 0, nil
	}

	if x.eofWrite {
		return 0, io.ErrClosedPipe
	}

	inf := 0
	sent := 0
	sup := _MaxTLSRecordSize_
	for {
		if sup > len(p) {
			sup = len(p)
		}

		if inf >= len(p) {
			break
		}

		record, err := x.specWrite.EncryptRec(tlssl.ContentTypeApplicationData,
			p[inf:sup])
		if err != nil {
			x.lg.Errorf("Error encrypting TLS record: %v", err)
			if !x.debugMode {
				return 0, err
			}

			record = nil
			x.lg.Debugf("RawWrite: %x", p[inf:sup])
		}

		offset := 0
		for {
			if record == nil {
				break
			}

			if offset >= len(record) {
				sent += len(p[inf:sup])
				break
			}

			n, err := x.rawConn.Write(record[offset:])
			if err != nil {
				x.lg.Errorf("Error writing TLS record: %v", err)
				return sent, err
			}

			offset += n
		}

		inf = sup
		sup += _MaxTLSRecordSize_
	}

	return sent, nil
}

func (x *xTLSConn) Close() error {

	defer x.rawConn.Close()
	x.eofWrite = true
	record, err := x.specWrite.EncryptRec(tlssl.ContentTypeAlert, _CloseNotify_)
	if err != nil {
		x.lg.Warnf("Error encrypting close notify record: %v", err)
		return err
	}

	// Theorically we should always send a close_notify alert but if the peer
	// is not waiting for it then doing so will trigger a reset on the
	// connection (which is ok, but we want to avoid it if possible). Optimal
	// solution would be to check for write half to be open but i couldn't find
	// a way to do it with net.Conn interface.
	if !x.peerClose {
		_, err = x.rawConn.Write(record)
		x.rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		fmt.Println("Esperando respuesta del peer...")
		n, _ := x.rawConn.Read(buf)
		if n >= tlssl.TLS_HEADER_SIZE && buf[0] == 0x15 {
			x.eofRead = true
			x.peerClose = true
		}

		x.rawConn.SetReadDeadline(time.Time{})
	}

	return err
}

func (x *xTLSConn) SetDeadline(t time.Time) error {
	return x.rawConn.SetDeadline(t)
}

func (x *xTLSConn) SetReadDeadline(t time.Time) error {
	return x.rawConn.SetReadDeadline(t)
}

func (x *xTLSConn) SetWriteDeadline(t time.Time) error {
	return x.rawConn.SetWriteDeadline(t)
}

func (x *xTLSConn) LocalAddr() net.Addr {
	return x.rawConn.LocalAddr()
}

func (x *xTLSConn) RemoteAddr() net.Addr {
	return x.rawConn.RemoteAddr()
}

func (x *xTLSConn) handleAlert(record []byte) {

	x.eofRead = true
	pt, err := x.specRead.DecryptRec(record)
	if err != nil {
		x.lg.Error("Error decrypting alert record: ", err)
		return
	}

	if len(pt) != 2 {
		x.lg.Errorf("Received unknown alert record: %x", pt)
		return
	}

	// is it a close_notify alert?
	if pt[0] == 0x01 && pt[1] == 0x00 {
		x.lg.Warn("Received close_notify alert from peer")
		x.peerClose = true
		return
	} else {
		x.lg.Errorf("Received Alert: %v - %v", names.TLSLevels[pt[0]],
			names.TLSAlerts[pt[1]])
	}
}
