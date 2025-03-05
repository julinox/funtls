package tester

import (
	"testing"
	"tlesio/tlssl"
)

func TestTlsRecordDecoder(t *testing.T) {
	buff := certificate()
	buff = append(buff, changeCipherSpec()...)
	buff = append(buff, clientKeyExchange()...)
	buff = append(buff, certificateVerify()...)
	buff = append(buff, finished()...)
	_, err := tlssl.TLSRecordsDecode(buff)
	if err != nil {
		t.Error(err)
	}
}
