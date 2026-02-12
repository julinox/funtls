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

	//"github.com/julinox/funtls/tlssl/keyexchange"
	kx "github.com/julinox/funtls/tlssl/keyexchange"
	"github.com/julinox/funtls/tlssl/names"
)

/*
El lg.info("suite registered") en 'initTLSSuites' (server.go) que se imprima
en la inicializacion de la suite y que imprima el cert match que se encontro
para la suite, ya eso ocurre pero primero se imprimen los matchs y luego los
registered
*/
func mano() {

	sg := []uint16{names.X25519, names.X448, names.SECP256R1,
		names.SECP384R1, names.SECP521R1}

	opts := &kx.ECKXConfig{
		SG: sg,
		//Tax: names.SECP256R1,
	}

	kxParams, err := kx.ECXKInit(opts)
	if err != nil {
		fmt.Println("error creacion: ", err)
		return
	}

	fmt.Printf("%x\n", kx.ECKXServerParams(kxParams))
}

// Lee esto: https://x.com/popovicu94/status/1988839738523152487
func main() {

	lg := server.InitDefaultLogger()
	srv, err := server.FunTLServe(&server.FunTLSCfg{
		Logger: lg,
		Certos: []*pki.CertPath{
			{
				ChainPath: "/data/seagate/codigo/golang/workspace/funtls/cmd/selfsigned/ecdsacert.pem",
				KeyPath:   "/data/seagate/codigo/golang/workspace/funtls/cmd/selfsigned/ecdsakey.pem",
			},
			{
				ChainPath: "/data/seagate/codigo/golang/workspace/funtls/cmd/selfsigned/rsacert.pem",
				KeyPath:   "/data/seagate/codigo/golang/workspace/funtls/cmd/selfsigned/rsakey.pem",
			},
		},
	})

	if err != nil {
		fmt.Println(err)
		return
	}

	//hearit, err := srv.Accept()
	_, err = srv.Accept()
	if err != nil {
		return
	}

	//curly(hearit)
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
