package suites

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"tlesio/systema"
	"tlesio/tlssl/suite"

	"github.com/sirupsen/logrus"
)

type x0x003D struct {
	lg *logrus.Logger
}

func NewAES_256_CBC_SHA256(lg *logrus.Logger) suite.Suite {
	if lg == nil {
		return nil
	}

	return &x0x003D{
		lg: lg,
	}
}

func (x *x0x003D) ID() uint16 {
	return 0x003D
}

func (x *x0x003D) Name() string {
	return "TLS_RSA_WITH_AES_256_CBC_SHA256"
}

func (x *x0x003D) Info() *suite.SuiteInfo {
	return &suite.SuiteInfo{
		Mac:         suite.HMAC,
		Mode:        suite.CBC,
		Hash:        suite.SHA256,
		Cipher:      suite.AES,
		KeySize:     32,
		KeySizeHMAC: 32,
		IVSize:      aes.BlockSize,
		Auth:        suite.RSA,
		KeyExchange: suite.RSA,
	}
}

// Cipher and MAC
func (x *x0x003D) Cipher(sc *suite.SuiteContext) ([]byte, error) {

	var err error
	var cipherText []byte

	err = x.basicCheck(sc)
	if err != nil {
		return nil, err
	}

	switch sc.MacMode {
	case suite.ETM:
		fmt.Println("ETM")

	case suite.MTE: // MTE
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

func (x *x0x003D) CipherNot(sc *suite.SuiteContext) ([]byte, error) {

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
	switch sc.MacMode {
	case suite.ETM:
		fmt.Println("DECIPHER ETM")

	case suite.MTE:
		// AESCBC^-1(CiphertText) = Plaintext || HMAC
		plainTextHmac, err := aesCBC(sc.Data, sc.Key, sc.IV, false)
		if err != nil {
			return nil, err
		}

		err = x.isAuthenticated(plainTextHmac, sc.HKey)
		if err != nil {
			return nil, err
		}

		return plainTextHmac[:len(plainTextHmac)-sha256.Size], nil

	default:
		return nil, fmt.Errorf("no specific mode to decipher")
	}

	return nil, nil
}

func (x *x0x003D) MacMe(cc *suite.SuiteContext) ([]byte, error) {

	if len(cc.HKey) == 0 {
		return nil, fmt.Errorf("nil/empty MAC Key")
	}

	hmacHash := hmac.New(sha256.New, cc.HKey)
	hmacHash.Write(cc.Data)
	return hmacHash.Sum(nil), nil
}

func (x *x0x003D) basicCheck(cc *suite.SuiteContext) error {

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

// Check if given text is authenticated
func (x *x0x003D) isAuthenticated(data, hkey []byte) error {

	if len(data) < sha256.Size {
		return fmt.Errorf("invalid data size")
	}

	given := data[len(data)-sha256.Size:]
	clearText := data[:len(data)-sha256.Size]
	expected, err := x.MacMe(&suite.SuiteContext{Data: clearText, HKey: hkey})
	if err != nil {
		return err
	}

	if !hmac.Equal(given, expected) {
		return fmt.Errorf("invalid HMAC")
	}

	return nil
}
