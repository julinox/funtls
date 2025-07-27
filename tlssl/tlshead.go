package tlssl

import (
	"fmt"
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

type TLSRecord struct {
	Msg       []byte
	Header    *TLSHeader
	HandShake *TLSHeaderHandshake
}

// Checks if the buffer contains a valid TLS record
// Returns a TLSRecord object if valid, otherwise returns an error
func TLSRecordMe(buffer []byte) (*TLSRecord, error) {

	var tlsHeader *TLSHeader
	if len(buffer) < TLS_HEADER_SIZE {
		return nil, fmt.Errorf("buffer 2short for TLSRECORD")
	}

	tlsHeader = TLSHead(buffer[:TLS_HEADER_SIZE])
	if tlsHeader.ContentType != ContentTypeHandshake &&
		tlsHeader.ContentType != ContentTypeAlert &&
		tlsHeader.ContentType != ContentTypeApplicationData {
		return nil, fmt.Errorf("invalid ContentType")
	}

	if tlsHeader.Version != TLS_VERSION1_2 {
		return nil, fmt.Errorf("invalid TLS version")
	}

	if tlsHeader.Len < 0 || tlsHeader.Len > len(buffer)-TLS_HEADER_SIZE {
		return nil, fmt.Errorf("invalid record length")
	}

	return &TLSRecord{
		Header: tlsHeader,
		Msg:    buffer[TLS_HEADER_SIZE : TLS_HEADER_SIZE+tlsHeader.Len],
	}, nil
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

// Decode TLS records from a buffer
// The buffer is a concatenation of TLS records
// If any "record" is invalid, the function returns error
func TLSRecordsDecode(buff []byte) ([]*TLSRecord, error) {

	var offset int
	var records []*TLSRecord

	// offset always points to the start of the next record
	for offset < len(buff) {
		record := TLSRecord{}
		head := TLSHead(buff[offset : offset+TLS_HEADER_SIZE])
		if head == nil {
			return nil, fmt.Errorf("nil TLSHeader object")
		}

		record.Header = head
		if head.Len > len(buff[offset:]) {
			return nil, fmt.Errorf("invalid record len. Is this an attack?")
		}

		// TLSRecord.Msg is the whole message
		record.Msg = buff[offset : offset+head.Len+TLS_HEADER_SIZE]
		if head.ContentType == ContentTypeHandshake {
			handshake := TLSHeadHandShake(buff[offset+TLS_HEADER_SIZE:])
			if handshake == nil {
				return nil, fmt.Errorf("nil TLSHeaderHandshake object")
			}

			record.HandShake = handshake
		}

		records = append(records, &record)
		offset += TLS_HEADER_SIZE + head.Len
	}

	return records, nil
}

func (x *TLSHeader) String() string {

	return fmt.Sprintf("ContentType: %v, Version: %v, Len: %d",
		x.ContentType, version(x.Version), x.Len)
}

func (x *TLSHeaderHandshake) String() string {

	return fmt.Sprintf("HandshakeType: %d, Len: %d",
		x.HandshakeType, x.Len)
}

func (x ContentTypeType) String() string {

	switch x {
	case ContentTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case ContentTypeAlert:
		return "Alert"
	case ContentTypeHandshake:
		return "Handshake"
	case ContentTypeApplicationData:
		return "ApplicationData"
	}

	return "Unknown"
}

func (x HandshakeTypeType) String() string {

	switch x {
	case HandshakeTypeClientHello:
		return "ClientHello"
	case HandshakeTypeServerHello:
		return "ServerHello"
	case HandshakeTypeCertificate:
		return "Certificate"
	case HandshakeTypeServerKeyExchange:
		return "ServerKeyExchange"
	case HandshakeTypeCertificateRequest:
		return "CertificateRequest"
	case HandshakeTypeServerHelloDone:
		return "ServerHelloDone"
	case HandshakeTypeCertificateVerify:
		return "CertificateVerify"
	case HandshakeTypeClientKeyExchange:
		return "ClientKeyExchange"
	case HandshakeTypeFinished:
		return "Finished"
	}

	return "Unknown"
}

func version(v uint16) string {

	switch v {
	case TLS_VERSION1_0:
		return "TLS 1.0(0x0301)"
	case TLS_VERSION1_1:
		return "TLS 1.1(0x0302)"
	case TLS_VERSION1_2:
		return "TLS 1.2(0x0303)"
	}

	return "Unknown"
}
