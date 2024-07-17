package utils

import (
	"sync"

	sigstoreRoot "github.com/sigstore/sigstore-go/pkg/root"
	sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
)

var (
	// cache the default Sigstore TUF client.
	defaultSigstoreTUFClient *sigstoreTUF.Client
	// defaultSigstoreTUFClientOnce is used for initializing the defaultSigstoreTUFClient.
	defaultSigstoreTUFClientOnce sync.Once

	// cache the trusted root.
	trustedRoot *sigstoreRoot.TrustedRoot
	// trustedRootOnce is used for initializing the trustedRoot.
	trustedRootOnce sync.Once
)

// SigstoreTUFClient is the interface for the Sigstore TUF client.
type SigstoreTUFClient interface {
	// GetTarget retrieves the target file from the TUF repository.
	GetTarget(target string) ([]byte, error)
}

// GetDefaultSigstoreTUFClient returns the default Sigstore TUF client.
// The client will be cached in memory.
func GetDefaultSigstoreTUFClient() (*sigstoreTUF.Client, error) {
	var err error
	defaultSigstoreTUFClientOnce.Do(func() {
		defaultSigstoreTUFClient, err = sigstoreTUF.DefaultClient()
		if err != nil {
			defaultSigstoreTUFClientOnce = sync.Once{}
			return
		}
	})
	if err != nil {
		return nil, err
	}
	return defaultSigstoreTUFClient, nil
}

// GetSigstoreTrustedRoot returns the trusted root for the Sigstore TUF client.
func GetSigstoreTrustedRoot() (*sigstoreRoot.TrustedRoot, error) {
	client, err := GetDefaultSigstoreTUFClient()
	if err != nil {
		return nil, err
	}
	trustedRootOnce.Do(func() {
		trustedRoot, err = sigstoreRoot.GetTrustedRoot(client)
		if err != nil {
			trustedRootOnce = sync.Once{}
		}
	})
	if err != nil {
		return nil, err
	}
	return trustedRoot, nil
}
