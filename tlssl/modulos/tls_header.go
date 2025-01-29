package modulos

import (
	"fmt"
	"tlesio/systema"

	"github.com/sirupsen/logrus"
)

type ContentTypeType uint8

const (
	ContentTypeChangeCipherSpec ContentTypeType = 20
	ContentTypeAlert            ContentTypeType = 21
	ContentTypeHandshake        ContentTypeType = 22
	ContentTypeApplicationData  ContentTypeType = 23
)

type ConfigTLSHeader struct {
	Lg *logrus.Logger
}

type DataTLSHeader struct {
	Version     uint16
	Length      uint16
	ContentType ContentTypeType
}

type tlsHeader struct {
	lg *logrus.Logger
}

func ModuleTLSHeader(cfg interface{}) (Modulo, error) {

	var modd tlsHeader

	data, ok := cfg.(ConfigTLSHeader)
	if !ok {
		return nil, ReturnErr(modd.Name(), "init config cast")
	}

	if data.Lg == nil {
		return nil, systema.ErrNilLogger
	}

	modd.lg = data.Lg
	modd.lg.Warn("Module 0xFFFA initialized")
	return &modd, nil
}

func (fa *tlsHeader) ID() uint16 {
	return 0xfffa
}

func (fa *tlsHeader) Name() string {
	return "tls_header"
}

func (fa *tlsHeader) Print() string {
	return "tls_header"
}

func (fa *tlsHeader) PrintRaw(data []byte) string {
	return fmt.Sprintf("%v", data)
}

func (fa *tlsHeader) GetConfig() interface{} {
	return nil
}

func (fa *tlsHeader) Execute(data interface{}) interface{} {
	return nil
}

func (fa *tlsHeader) LoadData(data interface{}) (interface{}, error) {

	var newHeader DataTLSHeader

	buffer, ok := data.([]byte)
	if !ok {
		return nil, ReturnErr(fa.Name(), "error casting []byte")
	}

	if len(buffer) != 5 {
		return nil, ReturnErr(fa.Name(), "header size did not match 5 bytes")
	}

	newHeader.ContentType = ContentTypeType(buffer[0])
	newHeader.Version = uint16(buffer[1])<<8 | uint16(buffer[2])
	newHeader.Length = uint16(buffer[3])<<8 | uint16(buffer[4])
	return &newHeader, nil
}

func (th *DataTLSHeader) PrintVersion() string {

	switch th.Version {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return "Is this TLS?"
	}
}

func (th *DataTLSHeader) String() string {
	return fmt.Sprintf("Version: %v | ContentType: %v | PayloadLen: %v",
		th.PrintVersion(), th.ContentType, th.Length)
}

func (c ContentTypeType) String() string {

	switch c {
	case ContentTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case ContentTypeAlert:
		return "Alert"
	case ContentTypeHandshake:
		return "Handshake"
	case ContentTypeApplicationData:
		return "ApplicationData"
	default:
		return "Unknow TLS Content Type"
	}
}
