package extensions

import (
	"fmt"
)

// Map of cipher suite numbers to their names
func CipherSuiteName(suite uint16) string {

	if name, exists := CipherSuiteNames[suite]; exists {
		return name
	}

	return fmt.Sprintf("Unknown Cipher Suite (0x%04X)", suite)
}

func PrintCipherSuiteNames(suites []uint16) string {

	var result string

	for i, suite := range suites {
		if i > 0 {
			result += "\n"
		}

		result += fmt.Sprintf("0x%04X: %s", suite, CipherSuiteName(suite))
	}

	return result
}
