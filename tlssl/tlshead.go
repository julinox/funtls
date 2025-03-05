package tlssl

import "fmt"

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
// ChangeCipherSpec: 0x14
// Alert: 0x15
// Handshake: 0x16
// Application Data: 0x17
// ------------------

// Versions:
// ------------------
// TLS 1.0: 0x0301
// TLS 1.1: 0x0302
// TLS 1.2: 0x0303
// TLS 1.3: 0x0303 (is determined by the extension "supported_versions" field)
// ------------------

// Each handshake message has the following structure:
//
// | Field             | Size (bytes) | Description|
// |-------------------|--------------|--------------------------|
// | HandshakeType     | 1 byte       | ClientHello: 0x01        |
// |                   |              | ServerHello: 0x02        |
// |                   |              | Certificate: 0x0B        |
// |                   |              | ServerKeyExchange: 0x0C  |
// |                   |              | CertificateRequest: 0x0D |
// |                   |              | ServerHelloDone: 0x0E    |
// |                   |              | CertificateVerify: 0x0F  |
// |                   |              | ClientKeyExchange: 0x10  |
// |                   |              | Finished: 0x14           |
// |-------------------|--------------|--------------------------|
// | Length            | 3 bytes      | Len of the message   ... |
// |-------------------|--------------|------------------------ -|
// | Handshake Message | Variable     | .                        |
// |-------------------------------------------------------------|

type ContentTypeType uint8
type HandshakeTypeType uint8

const (
	TLS_HEADER_SIZE    = 5
	TLS_HANDSHAKE_SIZE = 4
	TLS_VERSION1_0     = 0x0301
	TLS_VERSION1_1     = 0x0302
	TLS_VERSION1_2     = 0x0303
)

const (
	ContentTypeChangeCipherSpec ContentTypeType = 0x14
	ContentTypeAlert            ContentTypeType = 0x15
	ContentTypeHandshake        ContentTypeType = 0x16
	ContentTypeApplicationData  ContentTypeType = 0x17
)

const (
	HandshakeTypeClientHello        HandshakeTypeType = 0x01
	HandshakeTypeServerHello        HandshakeTypeType = 0x02
	HandshakeTypeCertificate        HandshakeTypeType = 0x0B
	HandshakeTypeServerKeyExchange  HandshakeTypeType = 0x0C
	HandshakeTypeCertificateRequest HandshakeTypeType = 0x0D
	HandshakeTypeServerHelloDone    HandshakeTypeType = 0x0E
	HandshakeTypeCertificateVerify  HandshakeTypeType = 0x0F
	HandshakeTypeClientKeyExchange  HandshakeTypeType = 0x10
	HandshakeTypeFinished           HandshakeTypeType = 0x14
)

type TLSHeader struct {
	ContentType ContentTypeType
	Version     uint16
	Len         int
}

type TLSHeaderHandshake struct {
	Len           int
	HandshakeType HandshakeTypeType
}

func TLSHead(buffer []byte) *TLSHeader {

	var header TLSHeader

	if len(buffer) < 5 {
		return nil
	}

	header.ContentType = ContentTypeType(buffer[0])
	header.Version = uint16(buffer[1])<<8 | uint16(buffer[2])
	header.Len = int(buffer[3])<<8 | int(buffer[4])
	return &header
}

func TLSHeadHandShake(buffer []byte) *TLSHeaderHandshake {

	var handshake TLSHeaderHandshake

	if len(buffer) < 4 {
		return nil
	}

	handshake.HandshakeType = HandshakeTypeType(buffer[0])
	handshake.Len = int(buffer[1])<<16 | int(buffer[2])<<8 | int(buffer[3])
	return &handshake
}

func TLSHeadPacket(hh *TLSHeader) []byte {

	var newBuffer []byte

	if hh == nil {
		return nil
	}

	newBuffer = append(newBuffer, byte(hh.ContentType))
	if hh.Version != 0 {
		newBuffer = append(newBuffer, byte(hh.Version>>8), byte(hh.Version))
	} else {
		newBuffer = append(newBuffer, 0x03, 0x03)
	}

	newBuffer = append(newBuffer, byte(hh.Len>>8), byte(hh.Len))
	return newBuffer
}

func TLSHeadHandShakePacket(hs *TLSHeaderHandshake) []byte {

	var newBuffer []byte

	if hs == nil {
		return nil
	}

	newBuffer = append(newBuffer, byte(hs.HandshakeType))
	newBuffer = append(newBuffer, byte(hs.Len>>16), byte(hs.Len>>8),
		byte(hs.Len))
	return newBuffer
}

func TLSHeadsHandShakePacket(ht HandshakeTypeType, buffLen int) []byte {

	newBuffer := TLSHeadPacket(&TLSHeader{
		ContentType: ContentTypeHandshake,
		Version:     TLS_VERSION1_2,
		Len:         buffLen + TLS_HANDSHAKE_SIZE})

	newBuffer = append(newBuffer, TLSHeadHandShakePacket(&TLSHeaderHandshake{
		Len:           buffLen,
		HandshakeType: ht})...)

	return newBuffer
}

func TLSHeadCheck(head *TLSHeader) error {

	if head == nil {
		return fmt.Errorf("nil TLSHeader object")
	}

	if head.Version != TLS_VERSION1_0 &&
		head.Version != TLS_VERSION1_1 &&
		head.Version != TLS_VERSION1_2 {
		return fmt.Errorf("invalid TLS version")
	}

	switch head.ContentType {
	case ContentTypeChangeCipherSpec:
		fallthrough
	case ContentTypeAlert:
		fallthrough
	case ContentTypeHandshake:
		fallthrough
	case ContentTypeApplicationData:
		break
	default:
		return fmt.Errorf("invalid ContentType")
	}

	return nil
}
