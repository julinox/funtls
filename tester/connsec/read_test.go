package connsec

import (
	"fmt"
	"net"
	"testing"
)

type simulador struct {
	net.Conn
}

func TestTLSRead(t *testing.T) {
	// Create a new TLSConn instance
	/*conn, _ := tlssl.NewTLSConn(nil)

	// Check if the connection is nil
	if conn == nil {
		t.Errorf("Expected non-nil TLSConn, got nil")
	}

	n, err := conn.Read(testData())
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	t.Log("Read bytes:", n)*/
}

func (s *simulador) Read(b []byte) (int, error) {
	// Simulate reading data into the buffer
	/*data := testData()
	copy(b, data)
	return len(data), nil*/
	fmt.Println("Simulateste")
	return 0, nil
}

func testData() []byte {

	data := []byte{
		// Registro 1: 10 bytes
		0x17, 0x03, 0x03, 0x00, 0x0A, // header
		0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // cuerpo

		// Registro 2: 8 bytes
		0x17, 0x03, 0x03, 0x00, 0x08,
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33,

		// Registro 3: 5 bytes
		0x17, 0x03, 0x03, 0x00, 0x05,
		0xFA, 0xCE, 0xB0, 0x0C, 0x00,
	}

	return data
}

/*
func testTLSReadWithData(data []byte) {

	clientConn, serverConn := net.Pipe()
	go func() {
		defer clientConn.Close()
		clientConn.Write(data)
	}()

	tlsConn := &tlssl.TLSConn{}
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	if err != nil {
		log.Fatal("Read error:", err)
	}

	fmt.Printf("Read %d bytes: %x\n", n, buf[:n])
}
*/
