package keymaker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/julinox/funtls/tester"
	"github.com/julinox/funtls/tlssl"
	"github.com/julinox/funtls/tlssl/suite"
	"github.com/sirupsen/logrus"
)

// TLS_RSA_AES_256_CBC_SHA1
func TestSuiteFinished(t *testing.T) {

	lg := tester.TestLogger(logrus.DebugLevel)
	// Get all handshake messages
	handshakeMsgs := getHandshakeMsgs()
	lg.Debugf("Handshake messages: %x", handshakeMsgs)

	// Get the hash of all handshake messages
	hashedHandshakeMsgs := hashear(handshakeMsgs)
	lg.Infof("Hashed handshake messages: %x", hashedHandshakeMsgs)

	// Get the master secret
	masterSecret := getMasterSecret()
	lg.Debugf("Master secret: %x", masterSecret)

	// Get the keymaker
	km := theKeymaker()
	lg.Debugf("Keymaker: %v", km)

	// Get the PRF
	prf := km.PRF(masterSecret, "client finished", hashedHandshakeMsgs)
	verifyData1 := prf[:12]
	verifyData2 := verifyData()
	if bytes.Equal(verifyData1, verifyData2) {
		lg.Info("Verify data is correct")
	} else {
		lg.Error("Verify data is incorrect")
	}

}

func theKeymaker() tlssl.TheKeyMaker {

	km, err := tlssl.NewKeymaker(suite.SHA256, 32)
	if err != nil {
		// Abort
		os.Exit(1)
	}

	return km
}

// You can get this value from openssl (as a client) by running:
// openssl s_client -connect <host>:<port>. Should be printed
// as 'Master-Key' in the output
func getMasterSecret() []byte {

	masterKey := "9779F2D8E4DC6E66E0F24D685EB009502DAE2F765F19E1F8BD290E1E7206CA2006969E5BED2C50195CC2112ACC38EFD9"
	mk, _ := hex.DecodeString(masterKey)
	return mk
}

func getHandshakeMsgs() []byte {

	clientHello := "0100012003032c48e0cb34cde4bcf8255e3701520a2b3e6f40e78b3a6a83dbcdc00e27a13aa420878fd47ee6af7d1121727f0fad3bf9c74d7f7fe258cea30b443e49ed7edc02f5003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff01000099000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d0020c2585138b7329d1cbe36dc65c9c77b4bc319fe8596b7bdc94275ce89cd975413"
	serverHello := "0200003103030cba459cd4ae9bcd146a425b3c22cd7ce3ed0e16aa6567441b775d0559d3261800003d00000900230000ff01000100"
	certificate := "0b0003770003740003713082036d30820255a00302010202145fa7aa53ae1dab3a71f6b493ec2d93b47b9f80a8300d06092a864886f70d01010b05003054310b300906035504061302565a3113301106035504080c0a43616c69666f726e6961310d300b06035504070c0453414c41310b3009060355040b0c0249543114301206035504030c0b6a756c696e6f782e6e6574301e170d3235303230393131343734315a170d3235303331313131343734315a3054310b300906035504061302565a3113301106035504080c0a43616c69666f726e6961310d300b06035504070c0453414c41310b3009060355040b0c0249543114301206035504030c0b6a756c696e6f782e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100bbc2459e852f36d7dd6babc0faf17d3ac03bfda8afd787fb972995980c51dc748a88c09bf89fab99c4ae18154d722a09ff2a2022bdc4c84cc1508ad2624b318fe618fb53eb39b58ffaf17ed96c6ffb19cf156219d72de63a4b2916f8a4a16ac4e7bb343f3431ec4aeef04d553138e7860c2a8dbb96918826d36b714b2deb0ea298a3603b338b3518c974b6dbd690c8c5f4883464751aca6a7193d1b15620b9031759539dc6d80a267d3d90a0d7fb3c068d174935f14fc22aef46e419a53ae3607f77880fa0cb54f2894bfa1cebf5857ad5917b53968ba52ee291fa4983521230a9f3ae11580a2f6684a710c9bda9f08f41598510f73e727d2520aaad2ef516e90203010001a337303530140603551d11040d300b82096c6f63616c686f7374301d0603551d0e0416041493ade7bd169752d78a054a5ec8116cef87417a30300d06092a864886f70d01010b0500038201010043844b61504c27e19261b152a22b2aa058fed0496a373ca38789bea63a6e49f3175baaedc07fc56997cc43481a81eef7bee897bc53d45a3763da4b828f50ba63339be713a475d536cad98865e3d069a572700e3f5c3962f07d2a56814121a23b18e4f1e82c52688306c24952e42b542980f02452f333cace9cc983be79595c7579dcc0608e7d86827d25eed0e24e2b989a2a6607e77ab326915fab30abe819275012c11de85f70e6f1ec3eb1842f2b347fab74599720f8e5237437ec10a1914472f373ede9b85cf44f99b1d9ad38ad6efe3e98e66b3b81af976ec6b284c97ae75c752028f878c2482cc741084a0c4f20a990e57031cafb75ef9ab883d2dda913"
	serverHelloDone := "0e000000"
	clientKeyExchange := "10000102010068e788dc607e2a6e6ee9b586451b544315c8382dc8ff2614106b73e8655f06553a5100c00701cf3cbc3bc7c421713b37d40462a1b626f36c4ff237172701d9af1e5511f769f8011e1e9cb8c7758b0657b75c0fff593066315d40a6b50df02ead6c7293fa770279e3e5c5d2adf37cada99690dfbbc54c3f49c6e0230b7cdd924d819fa094ed428c5250aebb6d8c3072038382d13c3db4bfda929a33368e37ac598d3007c0b4a4be72db8e80fce45b8bb6767e36153e9bbebaa9f13d4c2a691ab2b1e554857ffcd498a1cd64bbcc871ddd7f1bc564c8886730d4f5ebc1c3738bc26daae86a0bb52b39c8087abb6eadcc3e8962d6df73605dcfb880049a51a11bca"

	handshakeMsgs := clientHello + serverHello + certificate +
		serverHelloDone + clientKeyExchange
	hm, _ := hex.DecodeString(handshakeMsgs)
	return hm
}

func hashear(data []byte) []byte {

	hash := sha256.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// You can get this value from Wireshark by Decrypting
// the TLS traffic (can be done by using the private
// key of the server and importing it to Wireshark)
func verifyData() []byte {

	verifyData := "f8d7d99a8947c8418229005a"
	vd, _ := hex.DecodeString(verifyData)
	return vd
}
