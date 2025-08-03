package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/julinox/funtls/server"
	"github.com/julinox/funtls/tlssl/modulos"
)

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

	//curly(hearit)
	//openssl(hearit)
	fileDownload(hearit)
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
