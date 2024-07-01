package utils

import (
	"sync"

	sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
)

var (
	// cache the default Sigstore TUF client.
	defaultSigstoreTUFClient SigstoreTUFClient
	// defaultSigstoreTUFClientOnce is used for initializing the defaultSigstoreTUFClient.
	defaultSigstoreTUFClientOnce sync.Once
)

// SigstoreTUFClient is the interface for the Sigstore TUF client.
type SigstoreTUFClient interface {
	// GetTarget retrieves the target file from the TUF repository.
	GetTarget(target string) ([]byte, error)
}

// GetDefaultSigstoreTUFClient returns the default Sigstore TUF client.
// The client will be cached in memory.
func GetDefaultSigstoreTUFClient() (SigstoreTUFClient, error) {
	var err error
	defaultSigstoreTUFClientOnce.Do(func() {
		defaultSigstoreTUFClient, err = sigstoreTUF.DefaultClient()
	})
	if err != nil {
		return nil, err
	}
	return defaultSigstoreTUFClient, nil
}
