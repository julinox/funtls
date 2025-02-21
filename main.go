package main

import (
	"fmt"
	thps "tlesio/server"

	stmac "github.com/julinox/statemaquina"
)

func main() {
	pp, _ := stmac.NewMaquinaEstado(nil)
	fmt.Println(pp)
	return
	thps.RealServidor()
}
