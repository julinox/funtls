package extensions

import (
	"tlesio/systema"
)

const (
	ECDSA_SECP256R1_SHA256 = 0x0403
	ECDSA_SECP384R1_SHA384 = 0x0503
	ECDSA_SECP521R1_SHA512 = 0x0603
	ED25519                = 0x0807
	ED448                  = 0x0808
	RSA_PSS_PSS_SHA256     = 0x0809
	RSA_PSS_PSS_SHA384     = 0x080A
	RSA_PSS_PSS_SHA512     = 0x080B
	RSA_PKCS1_SHA256       = 0x0401
	RSA_PKCS1_SHA384       = 0x0501
	RSA_PKCS1_SHA512       = 0x0601
	RSA_PSS_RSAE_SHA256    = 0x0804
	RSA_PSS_RSAE_SHA384    = 0x0805
	RSA_PSS_RSAE_SHA512    = 0x0806
)

var SignHashAlgorithms = map[uint16]string{
	ECDSA_SECP256R1_SHA256: "ecdsa_secp256r1_sha256",
	ECDSA_SECP384R1_SHA384: "ecdsa_secp384r1_sha384",
	ECDSA_SECP521R1_SHA512: "ecdsa_secp521r1_sha512",
	ED25519:                "ed25519",
	ED448:                  "ed448",
	RSA_PSS_PSS_SHA256:     "rsa_pss_pss_sha256",
	RSA_PSS_PSS_SHA384:     "rsa_pss_pss_sha384",
	RSA_PSS_PSS_SHA512:     "rsa_pss_pss_sha512",
	RSA_PSS_RSAE_SHA256:    "rsa_pss_rsae_sha256",
	RSA_PSS_RSAE_SHA384:    "rsa_pss_rsae_sha384",
	RSA_PSS_RSAE_SHA512:    "rsa_pss_rsae_sha512",
	RSA_PKCS1_SHA256:       "rsa_pkcs1_sha256",
	RSA_PKCS1_SHA384:       "rsa_pkcs1_sha384",
	RSA_PKCS1_SHA512:       "rsa_pkcs1_sha512",
}

type ExtSignAlgoData struct {
	Len   uint16
	Algos []uint16
}

type xExtSignAlgo struct {
}

func NewExtSignAlgo() Extension {
	return &xExtSignAlgo{}
}

func (x xExtSignAlgo) Name() string {
	return "Signature_Algorithms"
}

func (x xExtSignAlgo) ID() uint16 {
	return 0x000D
}

func (x xExtSignAlgo) LoadData(data []byte, sz int) (interface{}, error) {

	var offset uint16 = 2
	var newData ExtSignAlgoData
	newData.Len = uint16(data[0])<<8 | uint16(data[1])/2
	if len(data) < int(newData.Len) {
		return nil, systema.ErrInvalidData
	}

	newData.Algos = make([]uint16, 0)
	for i := 0; i < int(newData.Len); i++ {
		newData.Algos = append(newData.Algos,
			uint16(data[offset])<<8|uint16(data[offset+1]))
		offset += 2
	}

	return &newData, nil
}

func (x xExtSignAlgo) PrintRaw(data []byte) string {

	var length int
	var newStr string = "{"
	var offset uint16 = 2

	length = int(data[0])<<8 | int(data[1])/2
	if len(data) < length {
		return "Invalid Data"
	}

	for i := 0; i < length; i++ {
		id := uint16(data[offset])<<8 | uint16(data[offset+1])
		algo := SignHashAlgorithms[id]
		if algo == "" {
			algo = "*"
		}

		if i == length-1 {
			newStr += algo
		} else {
			newStr += algo + ","
		}

		offset += 2
	}

	newStr += "}"
	return newStr
}

func (x *xExtSignAlgo) PacketServerHelo(data interface{}) ([]byte, error) {
	return nil, nil
}
