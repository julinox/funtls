package tlssl

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const _MaxTLSRecordSize_ = 16384

type TLSConn struct {
	RawConn   net.Conn
	SpecRead  TLSCipherSpec
	SpecWrite TLSCipherSpec
	Lg        *logrus.Logger
	DebugMode bool // ignore fatal errors like decoding errors
}

// bytes.Buffer behaves like a stream buffer (i.e mantains an internal index
// and do the "unbuffer" when needed)
type xTLSConn struct {
	rawConn   net.Conn
	specRead  TLSCipherSpec
	specWrite TLSCipherSpec
	rawBuf    []byte
	readBuf   bytes.Buffer
	rMutex    sync.Mutex
	debugMode bool
	lg        *logrus.Logger
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

func (x *xTLSConn) Read(p []byte) (int, error) {

	fmt.Println("---------------------------------- X -----------------------")
	fmt.Println(x.rawConn)
	fmt.Println("---------------------------------- X -----------------------")
	return x.rawConn.Read(p)
}

func (x *xTLSConn) Read2(p []byte) (int, error) {

	// Partial reads means

	if len(p) == 0 {
		return 0, nil
	}

	for {
		if x.readBuf.Len() > 0 {
			break
		}

		tmp := make([]byte, 4096)
		n, err := x.rawConn.Read(tmp)
		if err != nil {
			return 0, err
		}

		x.rawBuf = append(x.rawBuf, tmp[:n]...)
		for {
			if len(x.rawBuf) < TLS_HEADER_SIZE {
				break
			}

			pktSz := int(x.rawBuf[3])<<8 | int(x.rawBuf[4])
			if pktSz > _MaxTLSRecordSize_ {
				return 0, fmt.Errorf("invalid record size")
			}

			if len(x.rawBuf) < pktSz+TLS_HEADER_SIZE {
				break
			}

			tpt, err := x.specRead.DecryptRecord(&TLSCipherText{
				Header:   TLSHead(x.rawBuf[:TLS_HEADER_SIZE]),
				Fragment: x.rawBuf[TLS_HEADER_SIZE : pktSz+TLS_HEADER_SIZE],
			})

			if err != nil {
				if !x.debugMode {
					return 0, err
				}

				// Discard record even if decryption fails (debug mode),
				// to keep processing
				x.lg.Error("Error decrypting TLS record: ", err)
				x.lg.Debugf("RawBuf: %x", x.rawBuf[:pktSz+TLS_HEADER_SIZE])
			}

			x.rawBuf = x.rawBuf[pktSz+TLS_HEADER_SIZE:]
			if tpt != nil {
				x.readBuf.Write(tpt.Fragment)
			}
		}
	}

	return x.readBuf.Read(p)
}

func (x *xTLSConn) Write(p []byte) (int, error) {
	return x.rawConn.Write(p)
}

func (x *xTLSConn) Close() error {
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
