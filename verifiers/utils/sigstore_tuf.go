package utils

import (
	"fmt"

	sigstoreTuf "github.com/sigstore/sigstore-go/pkg/tuf"
)

type SigstoreTufClient interface {
	GetTarget(target string) ([]byte, error)
}

// NewSigstoreTufClient gets a Sigstore TUF client, which itself is a wrapper around the official TUF client.
func NewSigstoreTufClient() (*sigstoreTuf.Client, error) {
	opts := sigstoreTuf.DefaultOptions()
	client, err := sigstoreTuf.New(opts)
	if err != nil {
		return nil, fmt.Errorf("creating SigstoreTuf client: %w", err)
	}
	return client, nil
}
