package suites

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"tlesio/systema"

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

func (x *x0x003D) Info() *SuiteInfo {
	return &SuiteInfo{
		Mac:         HMAC,
		Mode:        CBC,
		Hash:        SHA256,
		Cipher:      AES,
		KeySize:     32,
		Auth:        RSA,
		KeyExchange: RSA,
	}
}

// Cipher and MAC
func (x *x0x003D) Cipher(sc *SuiteContext) ([]byte, error) {

	var err error
	var cipherText []byte

	err = x.basicCheck(sc)
	if err != nil {
		return nil, err
	}

	switch sc.MacMode {
	case ETM:
		fmt.Println("ETM")

	case MTE: // MTE
		// 1 MAC = HMAC(Plaintext, HKey).
		// 2 Ciphertext = AESCBC(ClearText || MAC || Padding)
		// 3 Final = IV ∣∣ C
		mac, err := x.MacMe(sc)
		if err != nil {
			return nil, err
		}

		cipherText, err = aesCBC(append(sc.Data, mac...), sc.Key, sc.IV, true)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("no specific mode to cipher")
	}

	return append(sc.IV, cipherText...), nil
}

func (x *x0x003D) CipherNot(sc *SuiteContext) ([]byte, error) {

	// Data = IV ∣∣ CipherText

	if sc == nil || sc.Data == nil {
		return nil, systema.ErrNilParams
	}

	sc.IV = sc.Data[:aes.BlockSize]
	cipherText := sc.Data[aes.BlockSize:]
	if err := x.basicCheck(sc); err != nil {
		return nil, err
	}

	sc.Data = cipherText
	fmt.Println(sc.PrinteaRaw())
	switch sc.MacMode {
	case ETM:
		fmt.Println("DECIPHER ETM")

	case MTE:
		// 2° AESCBC^-1(CiphertText) = Plaintext || MAC || Padding
		// 3° Plaintext = 2° - 256bits - padding
		// 4° MAC = HMAC(Plaintext, HKey)

		clearText, err := aesCBC(sc.Data, sc.Key, sc.IV, false)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Decipher MTE: %x\n", clearText)

	default:
		return nil, fmt.Errorf("no specific mode to decipher")
	}

	return nil, nil
}

func (x *x0x003D) MacMe(cc *SuiteContext) ([]byte, error) {

	if len(cc.HKey) == 0 {
		return nil, fmt.Errorf("nil/empty MAC Key")
	}

	hmacHash := hmac.New(sha256.New, cc.HKey)
	hmacHash.Write(cc.Data)
	return hmacHash.Sum(nil), nil
}

func (x *x0x003D) basicCheck(cc *SuiteContext) error {

	if cc == nil || len(cc.Data) == 0 {
		return systema.ErrNilParams
	}

	if len(cc.Key) != x.Info().KeySize {
		return systema.ErrInvalidKeySize
	}

	if len(cc.IV) != aes.BlockSize {
		return systema.ErrInvalidIVSize
	}

	return nil
}
