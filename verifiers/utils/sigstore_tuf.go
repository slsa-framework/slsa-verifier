package utils

import (
	"fmt"

	sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
)

type SigstoreTUFClient interface {
	GetTarget(target string) ([]byte, error)
}

// NewSigstoreTUFClient gets a Sigstore TUF client, which itself is a wrapper around the official TUF client.
func NewSigstoreTUFClient() (*sigstoreTUF.Client, error) {
	opts := sigstoreTUF.DefaultOptions()
	client, err := sigstoreTUF.New(opts)
	if err != nil {
		return nil, fmt.Errorf("creating SigstoreTUF client: %w", err)
	}
	return client, nil
}
