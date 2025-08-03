package connsec

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/cipherspec"
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

		record, err := x.specWrite.EncryptRec(tlssl.ContentTypeApplicationData, p[inf:sup])
		if err != nil {
			x.lg.Errorf("Error encrypting TLS record: %v", err)
			if !x.debugMode {
				return 0, err
			}

			record = nil
			x.lg.Debugf("RawWrite: %x", p[inf:sup])
		}

		// Write the encrypted record to the underlying connection
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

		//fmt.Printf("Escribiendo: %x | REC: %x\n", p[inf:sup], record)
		inf = sup
		sup += _MaxTLSRecordSize_
	}

	return sent, nil
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

// Since the TLS record size is limited to 16K, we will
// pack the data into multiple TLS records if necessary.
func packTLSRecords(p []byte, cs cipherspec.CipherSpec) ([]byte, error) {

	var buffer []byte

	if len(p) <= 0 || cs == nil {
		return buffer, nil
	}

	limI := 0
	limS := _MaxTLSRecordSize_
	if len(p) < _MaxTLSRecordSize_ {
		limS = len(p)
	}

	rounds := math.Ceil(float64(len(p)) / float64(_MaxTLSRecordSize_))
	for i := 0; i < int(rounds); i++ {
		data, err := cs.EncryptRec(tlssl.ContentTypeApplicationData,
			p[limI:limS])
		if err != nil {
			return nil, err
		}

		buffer = append(buffer, data...)
		if limI >= len(p) {
			break
		}

		limI += _MaxTLSRecordSize_
		limS += _MaxTLSRecordSize_
		if limS > len(p) {
			limS = len(p)
		}
	}

	return buffer, nil
}
