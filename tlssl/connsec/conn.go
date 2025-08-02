package connsec

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/cipherspec"
	"github.com/sirupsen/logrus"
)

// const _MaxTLSRecordSize_ = 16384
const _MaxTLSRecordSize_ = 3

var _CloseNotify_ = []byte{0x01, 0x00}

type TLSConn struct {
	RawConn   net.Conn
	SpecRead  cipherspec.CipherSpec
	SpecWrite cipherspec.CipherSpec
	Lg        *logrus.Logger
	DebugMode bool // ignore fatal errors like decoding errors
}

// bytes.Buffer behaves like a stream buffer (i.e mantains an internal index
// and do the "unbuffer" when needed)
type xTLSConn struct {
	debugMode   bool
	eofRead     bool
	eofWrite    bool
	rawConn     net.Conn
	readRawBuf  []byte
	writeRawBuf []byte
	readBuf     bytes.Buffer
	writeBuf    bytes.Buffer
	lg          *logrus.Logger
	specRead    cipherspec.CipherSpec
	specWrite   cipherspec.CipherSpec
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

		// Verifico si hay una alerta activa
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
			// DEBUG
			if record[0] == byte(tlssl.ContentTypeAlert) {
				x.readRawBuf = x.readRawBuf[pktSz+tlssl.TLS_HEADER_SIZE:]
				x.eofRead = true
				break
			}
			// DEBUG

			plainText, err := x.specRead.DecryptRec(record)
			if err != nil {
				if !x.debugMode {
					return 0, err
				}

				// Discard record even if decryption fails (debug mode),
				// to keep processing
				x.lg.Error("Error decrypting TLS record: ", err)
				x.lg.Debugf("Raw: %x",
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

	var offset int

	if len(p) == 0 {
		return 0, nil
	}

	record, err := x.specWrite.EncryptRec(tlssl.ContentTypeApplicationData, p)
	if err != nil {
		x.lg.Errorf("Error encrypting TLS record: %v", err)
		return 0, err
	}

	fmt.Printf("Record: %x\n", record)
	offset = 0
	counter := 0 // just for debug purposes
	maximus := len(p)
	for {
		if offset >= maximus {
			break
		}

		if x.eofWrite {
			return 0, io.ErrClosedPipe
		}

		sent, err := x.rawConn.Write(p[offset:])
		if err != nil {
			return 0, err
		}

		offset += sent
		counter++
	}

	x.lg.Infof("Counter: %v", counter)
	return offset, nil
}

func (x *xTLSConn) Close() error {

	fmt.Println("CHEQUEAR SI OPEN Y SI SI ENVIAR CLOSENOTIFY")
	/*record, err := x.specWrite.EncryptRec(tlssl.ContentTypeAlert, _CloseNotify_)
	if err != nil {
		x.lg.Warnf("Error encrypting close notify record: %v", err)
	} else {
		if _, err := x.rawConn.Write(record); err != nil {
			x.lg.Warnf("Error writing close notify record: %v", err)
		}
	}*/

	return x.rawConn.Close()
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
