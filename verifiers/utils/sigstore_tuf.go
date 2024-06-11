package utils

import (
	"sync/atomic"

	sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
)

// cache the default Sigstore TUF client.
var defaultSigstoreTUFClientAtomicValue atomic.Value

// SigstoreTUFClient is the interface for the Sigstore TUF client.
type SigstoreTUFClient interface {
	// GetTarget retrieves the target file from the TUF repository.
	GetTarget(target string) ([]byte, error)
}

// GetDefaultSigstoreTUFClient returns the default Sigstore TUF client.
// The client will be cacehd in memory.
func GetDefaultSigstoreTUFClient() (SigstoreTUFClient, error) {
	value := defaultSigstoreTUFClientAtomicValue.Load()
	if value != nil {
		return value.(SigstoreTUFClient), nil
	}
	sigstoreTUFClient, err := sigstoreTUF.DefaultClient()
	if err != nil {
		return nil, err
	}
	defaultSigstoreTUFClientAtomicValue.Store(sigstoreTUFClient)
	return sigstoreTUFClient, nil
}
