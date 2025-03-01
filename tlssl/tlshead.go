package tlssl

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
// 0x0304: TLS 1.3a
// ------------------

// Each handshake message has the following structure:
//
// | Field             | Size (bytes) | Description                                              |
// |-------------------|--------------|----------------------------------------------------------|
// | HandshakeType     | 1 byte       | Type of handshake message. Example:                      |
// |                   |              | - 1: ClientHello                                         |
// |                   |              | - 2: ServerHello                                         |
// |                   |              | - 11: Certificate                                        |
// |                   |              | - 14: ServerHelloDone                                    |
// |                   |              | - 16: ClientKeyExchange                                  |
// |                   |              | - 20: Finished                                           |
// |-------------------|--------------|----------------------------------------------------------|
// | Length            | 3 bytes      | Len of the message (in bytes), excluding the type field. |
// |-------------------|--------------|----------------------------------------------------------|
// | Handshake Message | Variable     | The body of the message (varies according to the         |
// |                                  | handshake type).                                         |
// |---------------------------------------------------------------------------------------------|

type ContentTypeType uint8
type HandshakeTypeType uint8

const (
	TLS_HEADER_SIZE    = 5
	TLS_HANDSHAKE_SIZE = 4
	TLS_VERSION        = 0x0303
)

const (
	ContentTypeChangeCipherSpec ContentTypeType = 20
	ContentTypeAlert            ContentTypeType = 21
	ContentTypeHandshake        ContentTypeType = 22
	ContentTypeApplicationData  ContentTypeType = 23
)

const (
	HandshakeTypeClientHelo        HandshakeTypeType = 1
	HandshakeTypeServerHelo        HandshakeTypeType = 2
	HandshakeTypeCertificate       HandshakeTypeType = 11
	HandshakeTypeServerHeloDone    HandshakeTypeType = 14
	HandshakeTypeClientKeyExchange HandshakeTypeType = 16
	HandshakeTypeFinished          HandshakeTypeType = 20
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
		Version:     TLS_VERSION,
		Len:         buffLen + TLS_HANDSHAKE_SIZE})

	newBuffer = append(newBuffer, TLSHeadHandShakePacket(&TLSHeaderHandshake{
		Len:           buffLen,
		HandshakeType: ht})...)

	return newBuffer
}
