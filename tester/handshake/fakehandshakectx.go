package tester

import (
	"net"

	"github.com/julinox/funtls/tlssl/handshake"

	clog "github.com/julinox/consolelogrus"
	"github.com/sirupsen/logrus"
)

type testHandshakeCtx struct {
	handshake.HandShakeContext
	data *testHandshakeCtxData
}

type testHandshakeCtxData struct {
	expected int
	stage    int
	order    []int
	comms    net.Conn
}

func testCtxHandshake(data *testHandshakeCtxData) handshake.HandShakeContext {

	if data == nil || data.comms == nil {
		return nil
	}

	return &testHandshakeCtx{
		data: data,
	}
}

func (x *testHandshakeCtx) GetTransitionStage() int {
	return x.data.stage
}

func (x *testHandshakeCtx) SetTransitionStage(s int) {
	x.data.stage = s
}

func (x *testHandshakeCtx) GetComms() net.Conn {
	return x.data.comms
}

func (x *testHandshakeCtx) Order() []int {
	return x.data.order
}

func (x *testHandshakeCtx) PrintOrder() string {
	return handshake.HandshakeNameList(x.data.order)
}

func (x *testHandshakeCtx) Expected() int {
	return x.data.expected
}

func (x *testHandshakeCtx) UnAppendExpected(op int) {
	x.data.expected &= ^op
}

func (x *testHandshakeCtx) PrintExpected() string {

	var expected []int

	allExpected := []int{
		handshake.CERTIFICATE,
		handshake.CLIENTKEYEXCHANGE,
		handshake.CERTIFICATEVERIFY,
		handshake.CHANGECIPHERSPEC,
		handshake.FINISHED,
	}

	for _, v := range allExpected {
		if x.data.expected&v != 0 {
			expected = append(expected, v)
		}
	}

	return handshake.HandshakeNameList(expected)
}

func (x *testHandshakeCtx) SendCtxBuff([]int) error {
	return nil
}

func testLogger() *logrus.Logger {
	lg := clog.InitNewLogger(&clog.CustomFormatter{Tag: "TESTER"})
	lg.SetLevel(logrus.DebugLevel)
	return lg
}
