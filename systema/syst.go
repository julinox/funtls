package systema

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func GetLogLevel(envName string) logrus.Level {

	levelStr := strings.ToUpper(os.Getenv(strings.ToUpper(envName)))
	switch levelStr {
	case "TRACE":
		return logrus.TraceLevel
	case "DEBUG":
		return logrus.DebugLevel
	case "WARN":
		return logrus.WarnLevel
	case "ERROR":
		return logrus.ErrorLevel
	case "FATAL":
		return logrus.FatalLevel
	case "PANIC":
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
	}
}

// Print a byte array in a 'pretty' format
func PrettyPrintBytes(buffer []byte) string {

	var pretty string

	for i, b := range buffer {
		pretty += fmt.Sprintf("%02x ", b)
		if (i+1)%16 == 0 && i+1 != len(buffer) {
			pretty += "\n"
		}
	}

	return pretty
}

func FileExists(path string) bool {

	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func LoadCertificate(path string) (*x509.Certificate, error) {

	if path == "" {
		return nil, fmt.Errorf("empty path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

func LoadPrivateKey(path string) (crypto.PrivateKey, error) {

	if path == "" {
		return nil, fmt.Errorf("empty path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)

	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil

		default:
			return nil, fmt.Errorf("unknown private key type")
		}
	}

	return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
}

func ValidateKeyPair(cert *x509.Certificate, key crypto.PrivateKey) bool {

	if cert == nil || key == nil {
		return false
	}

	switch keyT := key.(type) {
	case *rsa.PrivateKey:
		return keyT.PublicKey.Equal(cert.PublicKey)

	case *ecdsa.PrivateKey:
		return keyT.PublicKey.Equal(cert.PublicKey)
	}

	return false
}

/*
case *ecdsa.PrivateKey:
        if cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
            return nil
        }
    case ed25519.PrivateKey:
        if cert.PublicKey.(ed25519.PublicKey).Equal(key.Public().(ed25519.PublicKey)) {
            return nil
        }
    default:
*/
