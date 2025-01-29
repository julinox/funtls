package tlssl

import (
	"fmt"
	hx "tlesio/tlssl/handshake"
)

func readRequest(ctrl *tlsio, buff []byte) (*hx.MsgHelloCli, error) {

	heloMsgCli, err := ctrl.hmods.CliHelo.Handle(buff)
	if err != nil {
		return nil, err
	}

	return heloMsgCli, nil
}

func writeRespone(ctrl *tlsio, buff []byte) error {

	heloMsgServer, err := ctrl.hmods.ServerHelo.Handle(nil)
	if err != nil {
		return err
	}

	fmt.Println(heloMsgServer)
	return nil
}
