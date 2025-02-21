package server

import (
	"fmt"

	stmac "github.com/julinox/statemaquina"
)

func (x *wkf) Start() {

	x.ssl.lg.Info("JJEEE")
	maq, _ := stmac.NewStateMaquina(nil)
	fmt.Println(maq)
}
