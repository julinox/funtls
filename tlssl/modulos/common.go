package modulos

import (
	"fmt"
	"strings"
)

func AlgoToName(varr, algo uint16) string {

	switch varr {
	case 0xFFFF:
		return fmt.Sprintf("%s(0x%04X)", CipherSuiteNames[algo], algo)

	case 0x000D:
		return fmt.Sprintf("%s(0x%04X)", _SignatureHashAlgorithms[algo], algo)
	}

	return "unknown_algorithm_name_or_type"
}

func AlgosToName(varr uint16, algos []uint16) string {

	var names []string

	for _, v := range algos {
		names = append(names, AlgoToName(varr, v))
	}

	return fmt.Sprintf("\n%s", strings.Join(names, "\n"))
}
