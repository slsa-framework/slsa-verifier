package options

import "os"

func ExperimentalEnabled() bool {
	return os.Getenv("SLSA_VERIFIER_EXPERIMENTAL") == "1"
}
