package main

import (
	"fmt"

	"github.com/julinox/funtls/server"
	"github.com/julinox/funtls/tlssl/modulos"
)

// b github.com/julinox/funtls/tlssl.(*xTLSConn).Read
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

	buffer := make([]byte, 4096)
	sz, err := hearit.Read(buffer)
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}

	lg.Infof("HTTP DATA (SUCCESS!): \n%s", string(buffer[:sz]))
}
