package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
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
		fmt.Println("Error accepting connection:", err)
		return
	}

	handleClient(hearit)
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	var contentLength int

	// Leer línea por línea los headers
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
}

//dlv exec ./funtls --headless --listen=127.0.0.1:2345 --api-version=2
