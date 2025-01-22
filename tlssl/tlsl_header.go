package tlssl

import (
	"fmt"
	"tlesio/systema"
)

// -------------------------------------------
// | Field       | Size   | Description       |
// |-------------|--------|-------------------|
// | ContentType | 1 byte | Payload Type      |
// |-------------|--------|-------------------|
// | Version     | 2 bytes| TLS version       |
// |-------------|--------|-------------------|
// | Length      | 2 bytes| Length of  payload|
// -------------------------------------------

// Content Types:
// ------------------
// ChangeCipherSpec
// Alert
// Handshake
// Application Data
// ------------------

// Versions:
// ------------------
// 0x0301: TLS 1.0
// 0x0302: TLS 1.1
// 0x0303: TLS 1.2
// 0x0304: TLS 1.3
// ------------------

type ContentTypeType uint8

const _TLSHeaderSize = 5

const (
	ContentTypeChangeCipherSpec ContentTypeType = 20
	ContentTypeAlert            ContentTypeType = 21
	ContentTypeHandshake        ContentTypeType = 22
	ContentTypeApplicationData  ContentTypeType = 23
)

type TLSHeader struct {
	Version     uint16
	Length      uint16
	ContentType ContentTypeType
}

func processHeader(ctrl *tlsio, buffer []byte) (*TLSHeader, error) {

	var newHeader TLSHeader

	if ctrl == nil {
		return nil, systema.ErrNilController
	}

	if ctrl.logg == nil {
		return nil, systema.ErrNilLogger
	}

	if buffer == nil || len(buffer) != 5 {
		return nil, fmt.Errorf("header size did not match 5 bytes")
	}

	newHeader.ContentType = ContentTypeType(buffer[0])
	newHeader.Version = uint16(buffer[1])<<8 | uint16(buffer[2])
	newHeader.Length = uint16(buffer[3])<<8 | uint16(buffer[4])
	ctrl.logg.Trace(&newHeader)
	return &newHeader, nil
}

func (th *TLSHeader) PrintVersion() string {

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

func (th *TLSHeader) String() string {
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
