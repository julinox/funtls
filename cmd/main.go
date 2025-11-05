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
	pki "github.com/julinox/funtls/tlssl/certpki"
)

func main() {

	lg := server.InitDefaultLogger()
	srv, err := server.FunTLServe(&server.FunTLSCfg{
		Logger: lg,
		Certos: []*pki.CertPath{
			{
				ChainPath: "/home/usery/ca/chains/server1chain.pem",
				KeyPath:   "/home/usery/ca/chains/private/server1chain.key",
			},
			{
				ChainPath: "/home/usery/ca/chains/server3chain.pem",
				KeyPath:   "/home/usery/ca/chains/private/server3chain.key",
			},
			{
				ChainPath: "/home/usery/ca/chains/server2chain.pem",
				KeyPath:   "/home/usery/ca/chains/private/server2chain.key",
			},
			{
				ChainPath: "/home/usery/ca/chains/server2rsachain.pem",
				KeyPath:   "/home/usery/ca/chains/private/server2rsachain.key",
			},
		},
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	return
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
	file, err := os.Open("/home/usery/unmb.bin")
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
