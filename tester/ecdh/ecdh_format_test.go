package ecdh

import (
	"math/big"
	"testing"
)

// Definiciones de constantes (basadas en IANA y NIST)
const (
	SignAlgECDSA byte = 0x03
)

// Estructura para generalizar las pruebas de curva
type signatureFormatTest struct {
	Name             string
	CurveSize        int // En bytes (ej: 32 para P-256)
	HashAlgID        byte
	ExpectedRSLen    int // 2 * CurveSize
	ExpectedTotalLen int // 2 * CurveSize + 4
	RInput           *big.Int
	SInput           *big.Int
}

// MOCK: La función a probar. Se asume que implementa la lógica de padding y ensamblaje.
// (En la implementación real, esta función usaría el crypto/ecdsa.Sign y serializaría R y S)
func createSignatureBlock(r, s *big.Int, curveSize int, hashAlgID byte) []byte {
	// --- LÓGICA DE SERIALIZACIÓN Y PADDING ---

	// 1. Padding y Concatenación de R y S
	rBytes := make([]byte, curveSize)
	sBytes := make([]byte, curveSize)
	r.FillBytes(rBytes)
	s.FillBytes(sBytes)
	signatureValue := append(rBytes, sBytes...)

	// 2. Ensamblaje del Bloque Header (4 bytes)
	totalRSLen := len(signatureValue)
	block := make([]byte, 0, totalRSLen+4)

	block = append(block, hashAlgID)
	block = append(block, SignAlgECDSA)

	// Longitud (big-endian de 2 bytes)
	block = append(block, byte(totalRSLen>>8), byte(totalRSLen))

	// 3. Payload (R || S)
	block = append(block, signatureValue...)

	return block
}

// Test principal que itera sobre las curvas NIST
func TestSignatureBlockFormat(t *testing.T) {
	// Valores que fuerzan el padding (R=1, S=256)
	rSmall := big.NewInt(1)
	sSmall := big.NewInt(256)

	tests := []signatureFormatTest{
		{
			Name:             "P-256_SHA256_ECDSA",
			CurveSize:        32,   // 256 bits
			HashAlgID:        0x04, // SHA-256
			ExpectedRSLen:    64,
			ExpectedTotalLen: 68,
			RInput:           rSmall,
			SInput:           sSmall,
		},
		{
			Name:             "P-384_SHA384_ECDSA",
			CurveSize:        48,   // 384 bits
			HashAlgID:        0x05, // SHA-384
			ExpectedRSLen:    96,
			ExpectedTotalLen: 100,
			RInput:           rSmall,
			SInput:           sSmall,
		},
		{
			Name:             "P-521_SHA512_ECDSA",
			CurveSize:        66,   // 521 bits (ceil(521/8) = 66)
			HashAlgID:        0x06, // SHA-512
			ExpectedRSLen:    132,
			ExpectedTotalLen: 136,
			RInput:           rSmall,
			SInput:           sSmall,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {

			// Llamada a la función a probar (simulada por mockCreateSignatureBlock)
			signatureBlock := createSignatureBlock(tt.RInput, tt.SInput, tt.CurveSize, tt.HashAlgID)

			// 1. Verificación de Longitud Total
			if len(signatureBlock) != tt.ExpectedTotalLen {
				t.Fatalf("FAIL: Longitud total. Esperada: %d, Obtenida: %d", tt.ExpectedTotalLen, len(signatureBlock))
			}

			// 2. Verificación del Header (Algoritmos y Longitud)

			// HashAlg (Byte 0)
			if signatureBlock[0] != tt.HashAlgID {
				t.Errorf("FAIL: HashAlg. Esperado: 0x%02x, Obtenido: 0x%02x", tt.HashAlgID, signatureBlock[0])
			}
			// SignAlg (Byte 1)
			if signatureBlock[1] != SignAlgECDSA {
				t.Errorf("FAIL: SignAlg. Esperado: 0x%02x, Obtenido: 0x%02x", SignAlgECDSA, signatureBlock[1])
			}
			// Longitud de Firma (Bytes 2-3)
			expectedLenMSB := byte(tt.ExpectedRSLen >> 8)
			expectedLenLSB := byte(tt.ExpectedRSLen)
			if signatureBlock[2] != expectedLenMSB || signatureBlock[3] != expectedLenLSB {
				t.Errorf("FAIL: Longitud. Esperada: 0x%02x 0x%02x, Obtenida: 0x%02x 0x%02x", expectedLenMSB, expectedLenLSB, signatureBlock[2], signatureBlock[3])
			}

			// 3. Verificación de Padding en R (comienza en el Byte 4)
			// El último byte de R (Byte 4 + CurveSize - 1) debe ser el valor de R (1)
			rEndIndex := 4 + tt.CurveSize - 1
			if signatureBlock[rEndIndex] != 0x01 {
				t.Errorf("FAIL: Padding R. Último byte (idx %d). Esperado: 0x01, Obtenido: 0x%02x", rEndIndex, signatureBlock[rEndIndex])
			}
			// El primer byte de R (Byte 4) debe ser relleno (0x00)
			if signatureBlock[4] != 0x00 {
				t.Errorf("FAIL: Padding R. Primer byte (idx 4). Esperado: 0x00, Obtenido: 0x%02x", signatureBlock[4])
			}

			// 4. Verificación de Padding en S
			// Los últimos dos bytes deben ser 0x01 y 0x00 (por S=256, 0x0100)
			sEndIndex := 4 + tt.ExpectedRSLen - 1
			if signatureBlock[sEndIndex] != 0x00 {
				t.Errorf("FAIL: Padding S. Último byte (idx %d). Esperado: 0x00, Obtenido: 0x%02x", sEndIndex, signatureBlock[sEndIndex])
			}
			if signatureBlock[sEndIndex-1] != 0x01 {
				t.Errorf("FAIL: Padding S. Penúltimo byte (idx %d). Esperado: 0x01, Obtenido: 0x%02x", sEndIndex-1, signatureBlock[sEndIndex-1])
			}
		})
	}
}
