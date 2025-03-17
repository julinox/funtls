package suites

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"tlesio/tlssl/suite"
)

type x0x003D struct {
}

func NewAES_256_CBC_SHA256() suite.Suite {

	return &x0x003D{}
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

	/*var err error
	var cipherText []byte

	err = x.basicCheck(sc)
	if err != nil {
		return nil, err
	}

	switch sc.MacMode {
	case suite.ETM:
		return nil, fmt.Errorf("no ETM yet")

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

	return append(sc.IV, cipherText...), nil*/
	return nil, nil
}

// AESCBC^-1(CiphertText) = Plaintext || HMAC
func (x *x0x003D) CipherNot(ctx *suite.SuiteContext) ([]byte, error) {

	if err := x.basicCheck(ctx); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("no specific mode to cipher")
}

func (x *x0x003D) modeMTE(ctx *suite.SuiteContext) ([]byte, error) {

	/*var mac []byte

	clearText, err := aesCBCDecrypt(ctx.Data, ctx.Key, ctx.IV)
	if err != nil {
		return nil, fmt.Errorf("MTE decrypt(%v): %v", x.Name(), err)
	}

	mac = clearText[len(clearText)-sha256.Size:]

	// Finished message
	if x.seqNumber == 0 {
		clearText = clearText[x.Info().IVSize:]
	}

	fmt.Printf("MAC? -> %x\n", mac)
	return clearText, nil*/

	return nil, nil
}

func (x *x0x003D) modeETM(ctx *suite.SuiteContext) ([]byte, error) {

	//mac = ctx.Data[len(ctx.Data)-sha256.Size : len(ctx.Data)]
	//ctx.Data = ctx.Data[:len(ctx.Data)-sha256.Size]
	return nil, fmt.Errorf("no ETM yet")
}

func (x *x0x003D) MacMe(cc *suite.SuiteContext) ([]byte, error) {

	if len(cc.HKey) == 0 {
		return nil, fmt.Errorf("nil/empty MAC Key")
	}

	hmacHash := hmac.New(sha256.New, cc.HKey)
	hmacHash.Write(cc.Data)
	return hmacHash.Sum(nil), nil
}

func (x *x0x003D) HashMe(data []byte) ([]byte, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("nil/empty data")
	}

	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil), nil
}

func (x *x0x003D) basicCheck(cc *suite.SuiteContext) error {

	if cc == nil || len(cc.Data) == 0 {
		return fmt.Errorf("nil/empty SuiteContext(%v)", x.Name())
	}

	if len(cc.Key) != x.Info().KeySize {
		return fmt.Errorf("invalid key size(%v)", x.Name())
	}

	if len(cc.IV) != aes.BlockSize {
		return fmt.Errorf("invalid IV size(%v)", x.Name())
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
