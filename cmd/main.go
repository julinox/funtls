package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/julinox/funtls/server"
	fcrypto "github.com/julinox/funtls/tlssl/crypto"
	"github.com/julinox/funtls/tlssl/modulos"
)

func main3() {

	gg := "/data/seagate/codigo/golang/workspace/funtls/cmd/pki2/server1chain.pem"
	_, err := fcrypto.ParseCertificate1(gg)
	if err != nil {
		fmt.Println(err)
		return
	}
}

/*func main6() {

	var suites = []uint16{
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA           → KX=RSA,     SIG=RSA
		0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     → KX=DHE,     SIG=RSA
		0x0032, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA        → KX=DHE,     SIG=DSS
		0xC009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    → KX=ECDHE,   SIG=ECDSA
		0xC014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      → KX=ECDHE,   SIG=RSA
		0xC003, // TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA     → KX=ECDH,    SIG=ECDSA
		0xC00A, // TLS_ECDH_RSA_WITH_AES_256_CBC_SHA       → KX=ECDH,    SIG=RSA
		0x0030, // TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA        → KX=DH,      SIG=RSA
		0x0031, // TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA        → KX=DH,      SIG=DSS
	}

	for _, cs := range suites {
		modulos.Pepito(cs)
		break
	}
}*/

func main() {

	lg := server.InitDefaultLogger()
	srv, err := server.FunTLServe(&server.FunTLSCfg{
		Logger: lg,
		Certs: []*modulos.CertInfo{
			{
				PathCert: "./pki/server1chain.pem",
				PathKey:  "./pki/server1key.pem",
			},
		},
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	hearit, err := srv.Accept()
	if err != nil {
		return
	}

	curly(hearit)
	//openssl(hearit)
	//fileDownload(hearit)
	//custom(hearit)
	//closing(hearit)
}

func closing(conn net.Conn) {

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("Error leyendo: %v\n", err)
		return
	}

	fmt.Printf("CN? %x\n", buf[:n])
	conn.Close()
}

func custom(conn net.Conn) {

	defer conn.Close()
	b := make([]byte, 2)
	n, err := io.ReadFull(conn, b)
	if err != nil || b[0] != 0xFE || b[1] != 0xFF {
		fmt.Println("Trigger inválido o error leyendo")
		return
	}

	fmt.Println("Trigger OK, enviando archivo...")
	f, err := os.Open("/home/usery/ungb.bin")
	if err != nil {
		fmt.Printf("Error abriendo archivo: %v\n", err)
		return
	}

	written, err := io.Copy(conn, f)
	if err != nil {
		fmt.Printf("Error enviando archivo: %v\n", err)
		return
	}

	fmt.Printf("Archivo enviado (%d bytes). Esperando cierre del cliente...\n", written)
	buf := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buf)
	if err == nil && n > 0 && buf[0] == 0x15 {
		fmt.Println("Recibido close_notify del cliente.")
	} else {
		fmt.Println("Cierre del cliente no detectado (timeout o no-alert).")
	}

	conn.SetReadDeadline(time.Time{}) // limpiar deadline
}

func curly(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Leer línea inicial (ej: GET / HTTP/1.1)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("error leyendo request: %s\n", err)
		return
	}
	if !strings.HasPrefix(line, "GET ") {
		fmt.Println("no es un GET")
		return
	}

	// Leer headers y descartarlos
	for {
		h, err := reader.ReadString('\n')
		if err != nil || h == "\r\n" {
			break
		}
	}

	// Respuesta simple
	body := []byte("<html><body><h1>FunTLS alive</h1></body></html>")

	conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n" +
		"\r\n"))
	conn.Write(body)
}

func openssl(conn net.Conn) {

	defer conn.Close()
	fmt.Println("conexión establecida desde:", conn.RemoteAddr())
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Println("error leyendo:", err)
		return
	}

	fmt.Printf("cliente dijo: %q\n", line)
}

func fileDownload(conn net.Conn) {
	defer conn.Close()

	// Leer y descartar el request
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}

	// Abrir archivo binario
	file, err := os.Open("/home/usery/ungb.bin")
	if err != nil {
		fmt.Fprintf(conn, "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer file.Close()

	// Obtener tamaño
	info, _ := file.Stat()
	size := info.Size()

	// Enviar headers
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\n"+
		"Content-Type: application/octet-stream\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n\r\n", size)

	// Enviar archivo
	io.Copy(conn, file)
}

// go build -gcflags="all=-N -l" -o funtls
//dlv exec ./funtls --headless --listen=127.0.0.1:2345 --api-version=2
