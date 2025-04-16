package tlssl

import (
	"net"
	"time"
)

type TLSConn struct {
	rawConn net.Conn
}

func NewTLSConn(raw net.Conn) (net.Conn, error) {

	return &TLSConn{
		rawConn: raw,
	}, nil
}

func (x TLSConn) Read(p []byte) (int, error) {
	return x.rawConn.Read(p)
}

func (x TLSConn) Write(p []byte) (int, error) {
	return x.rawConn.Write(p)
}

func (x TLSConn) Close() error {
	return x.rawConn.Close()
}

func (x TLSConn) SetDeadline(t time.Time) error {
	return x.rawConn.SetDeadline(t)
}

func (x TLSConn) SetReadDeadline(t time.Time) error {
	return x.rawConn.SetReadDeadline(t)
}

func (x TLSConn) SetWriteDeadline(t time.Time) error {
	return x.rawConn.SetWriteDeadline(t)
}

func (x TLSConn) LocalAddr() net.Addr {
	return x.rawConn.LocalAddr()
}

func (x TLSConn) RemoteAddr() net.Addr {
	return x.rawConn.RemoteAddr()
}
