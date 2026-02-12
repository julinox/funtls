package connsec

import (
	"fmt"
	"net"
	"testing"

	"encoding/hex"

	"github.com/julinox/funtls/tester"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/cipherspec"
	"github.com/julinox/funtls/tlssl/connsec"
	"github.com/julinox/funtls/tlssl/suite"
	"github.com/julinox/funtls/tlssl/suite/ciphersuites"
	"github.com/sirupsen/logrus"
)

type xConn struct {
	net.Conn
	count  int
	buffer []byte
}

func TestTLSWrite(t *testing.T) {

	var xc xConn

	xc.buffer = make([]byte, 0, 1024)
	newTConn, err := connsec.NewTLSConn(&connsec.TLSConn{
		RawConn:   &xc,
		SpecRead:  createCSpec(createCSuite(), clientKeys()),
		SpecWrite: createCSpec(createCSuite(), serverKeys()),
		Lg:        tester.TestLogger(logrus.DebugLevel),
		DebugMode: false,
	})

	if err != nil {
		t.Errorf("Error creating TLSConn: %v", err)
		return
	}

	n, err := newTConn.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A})
	if err != nil {
		t.Errorf("Error writing to TLSConn (Bytes Writenn: %v): %v", n, err)
		return
	}

	t.Logf("Bytes written (%v/%v): '%s'", n, len(xc.buffer), xc.buffer)
}

func createCSpec(st suite.Suite, keys *tlssl.Keys) cipherspec.CipherSpec {

	return cipherspec.NewCipherSpec(st, keys, tlssl.MODE_MTE)
}

func createCSuite() suite.Suite {
	return ciphersuites.RsaAes256CbcSha256(nil)
}

func clientKeys() *tlssl.Keys {

	return &tlssl.Keys{
		Hkey: strToHex("7ee3f5b9c3a5e57ebf76a8fa8fd7e8bf76d5bb659f53890656c7ec39c21a605d"),
		Key:  strToHex("6f8a428a98ee3d97a9771578054dbfab7b70ce2274a99951b9ecc284683a410a"),
		IV:   strToHex("328b0448cad8d31bd4706fbe1ce431ab"),
	}
}

func serverKeys() *tlssl.Keys {
	return &tlssl.Keys{
		Hkey: strToHex("ed1001764817bbc099298fb8d135ccb0ed012d1f8b57cdabac577b46524538a8"),
		Key:  strToHex("25841d92683f5df9670473c1d1ba1852eba46cc0bef51204c338d92cc8e0be0b"),
		IV:   strToHex("0d0f086c52bfe60bbe43e39a9a6fb14b"),
	}
}

func strToHex(str string) []byte {

	Hkey, err := hex.DecodeString(str)
	if err != nil {
		fmt.Printf("Error decoding hex string: %v\n", err)
		return nil
	}

	return Hkey
}

func (x *xConn) Write(b []byte) (int, error) {

	if x.count == 3 {
		return 0, fmt.Errorf("Simulated error on write")
	}

	fmt.Println("Llamada:", x.count)
	x.count++
	//return x.Write1(b)
	//return x.Write3(b)
	return x.WriteN(b)
}

func (x *xConn) WriteN(b []byte) (int, error) {
	return len(b), nil
}

func (x *xConn) Write1(b []byte) (int, error) {

	x.buffer = append(x.buffer, b[0:1]...)
	return 1, nil
}

func (x *xConn) Write3(b []byte) (int, error) {

	var offset int

	if len(b) > 3 {
		offset = 3
	} else {
		offset = len(b)
	}

	x.buffer = append(x.buffer, b[:offset]...)
	return offset, nil
}
