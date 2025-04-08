package tlssl

import "net"

/*
Read(p []byte) (n int, err error)
Write(p []byte) (n int, err error)
Close() error
SetDeadline(t time.Time) error
SetReadDeadline(t time.Time) error
SetWriteDeadline(t time.Time) error
*/

type TLSConn struct {
	rawConn           net.Conn
	handshakeComplete bool
	//cipher            CipherSuite // tu interfaz de cifrado ya implementada
	//state             connState   // flags, rol, etc.
	//readBuf           []byte
	//writeBuf          []byte
}

func NewTLSConn(conn net.Conn) *TLSConn {
	return &TLSConn{
		rawConn:           conn,
		handshakeComplete: false,
	}
}

// TLSConn representa una conexión TLS ya negociada, lista para leer/escribir.
/*

type connState struct {
	isClient          bool
	version           uint16
	handshakeComplete bool
}

func (c *TLSConn) Read(p []byte) (int, error) {
	if !c.handshakeComplete {
		return 0, errors.New("TLS handshake not complete")
	}
	// Leer, decifrar, verificar MAC, etc.
	return 0, nil
}

func (c *TLSConn) Write(p []byte) (int, error) {
	if !c.handshakeComplete {
		return 0, errors.New("TLS handshake not complete")
	}
	// Fragmentar, cifrar, aplicar MAC, enviar
	return 0, nil
}

func (c *TLSConn) Close() error {
	// Enviar close_notify si aplica
	return c.rawConn.Close()
}

func (c *TLSConn) SetDeadline(t time.Time) error {
	return c.rawConn.SetDeadline(t)
}

func (c *TLSConn) SetReadDeadline(t time.Time) error {
	return c.rawConn.SetReadDeadline(t)
}

func (c *TLSConn) SetWriteDeadline(t time.Time) error {
	return c.rawConn.SetWriteDeadline(t)
}

// NewTLSConn construye una nueva conexión TLS lista para uso (post-handshake).

*/
