package options

import (
	"os"
	"strconv"
)

// ExperimentalEnabled returns true if experimental features are currently
// enabled.
func ExperimentalEnabled() bool {
	if b, err := strconv.ParseBool(os.Getenv("SLSA_VERIFIER_EXPERIMENTAL")); err == nil {
		return b
	}
	return false
}

// TestingEnabled returns true if the SLSA_VERIFIER_TESTING environment
// variable is set.
func TestingEnabled() bool {
	if b, err := strconv.ParseBool(os.Getenv("SLSA_VERIFIER_TESTING")); err == nil {
		return b
	}
	return false
}
