package suites

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

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

	default: // MTE
		// 1 MAC = HMAC(Plaintext, HKey).
		// 2 Ciphertext = AESCBC(ClearText || MAC || Padding)
		// 3 Final = IV ∣∣ C
		mac, err := x.MacMe(sc)
		if err != nil {
			return nil, err
		}

		cipherText, err = aesCBC(append(sc.Data, mac...), sc.Key, sc.IV)
		if err != nil {
			return nil, err
		}
	}

	return append(sc.HKey, cipherText...), nil
}

func (x *x0x003D) CipherNot(sc *SuiteContext) ([]byte, error) {

	if err := x.basicCheck(sc); err != nil {
		return nil, err
	}

	if len(sc.Data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not multiple of block size")
	}

	block, err := aes.NewCipher(sc.Key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, sc.IV)
	mode.CryptBlocks(sc.Data, sc.Data)
	plainText, err := unpadPKCS7(sc.Data)
	if err != nil {
		return nil, err
	}

	return plainText, nil
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
		return fmt.Errorf("nil context/data")
	}

	if len(cc.Key) != x.Info().KeySize {
		return fmt.Errorf("nil/invalidSz key")
	}

	if len(cc.IV) != aes.BlockSize {
		return fmt.Errorf("nil/invalidSz IV")
	}

	return nil
}
