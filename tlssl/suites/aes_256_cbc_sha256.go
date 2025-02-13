package suites

import (
	"fmt"

	"github.com/sirupsen/logrus"
)

type x0x003D struct {
	lg *logrus.Logger
}

func NewAES_256_CBC_SHA256(lg *logrus.Logger) Suite {
	if lg == nil {
		return nil
	}

	return &x0x003D{lg}
}

func (x *x0x003D) ID() uint16 {
	return 0x003D
}

func (x *x0x003D) Name() string {
	return "TLS_RSA_WITH_AES_256_CBC_SHA256"
}

func (x *x0x003D) Cipher(*CipherContext) error {
	fmt.Println("CIPHER ->", x.Name())
	return nil
}

func (x *x0x003D) CipherNot(*CipherContext) error {
	fmt.Println("CIPHERNOT ->", x.Name())
	return nil
}

func (x *x0x003D) MacMe() {
	fmt.Println("MACME ->", x.Name())
}
