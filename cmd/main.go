package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

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

	realidad(hearit)
}

func realidad(conn net.Conn) {
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

// -------------------------------------------------------------------------------
func basico(conn net.Conn) {

	var buf bytes.Buffer
	tmp := make([]byte, 1024)
	data := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 13\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"Hello, world!")

	for {
		n, err := conn.Read(tmp)
		if err != nil {
			fmt.Printf("error leyendo: %s\n", err)
			return
		}

		buf.Write(tmp[:n])

		// Simple check: look for the end of HTTP headers (\r\n\r\n)
		if bytes.Contains(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}

	fmt.Printf("LEIDO: %s\n", buf.Bytes())
	conn.Write(data)
}

func handleClient(conn net.Conn) {

	var contentLength int

	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("error leyendo headers: %s\n", err)
			return
		}
		if line == "\r\n" {
			break
		}

		// Buscar Content-Length
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			val := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			contentLength, _ = strconv.Atoi(val)
		}
	}

	conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"))
	return
	if contentLength == 0 {
		fmt.Println(">> No se especificó Content-Length. Nada que leer.")
		return
	}

	// Leer el body exacto
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		fmt.Printf("error leyendo body: %s\n", err)
		return
	}

	fmt.Printf(">> Recibido %d bytes\n", len(body))
	h := sha256.Sum256(body)
	fmt.Printf(">> SHA-256 del body: %s\n", hex.EncodeToString(h[:]))
	fmt.Println()
	conn.Write([]byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"))
	//fmt.Println(">> Respuesta enviada al cliente.")
	time.Sleep(1 * time.Second) // Esperar un segundo antes de cerrar la conexión
}

// go build -gcflags="all=-N -l" -o funtls
//dlv exec ./funtls --headless --listen=127.0.0.1:2345 --api-version=2
