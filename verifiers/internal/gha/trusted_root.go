package gha

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync/atomic"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

// TrustedRoot struct that holds the verification material necessary
// to validate items. MUST be populated out of band.
type TrustedRoot struct {
	// RekorPubKeys is a map from log ID to public keys containing metadata.
	RekorPubKeys *cosign.TrustedTransparencyLogPubKeys

	// SctPubKeys is a map from log ID to public keys for the SCT.
	CTPubKeys *cosign.TrustedTransparencyLogPubKeys

	// Certificate pool for Fulcio roots.
	FulcioRoot *x509.CertPool

	// Certificate pool for Fulcio intermediates
	FulcioIntermediates *x509.CertPool
}

func getTrustedRoot(ctx context.Context) (*TrustedRoot, error) {
	rekorPubKeys, err := cosign.GetRekorPubs(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, err)
	}

	ctPubKeys, err := cosign.GetCTLogPubs(ctx)
	if err != nil {
		// this is unexpected, hold on to this error.
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInternal, err)
	}

	roots, err := fulcio.GetRoots()
	if err != nil {
		// this is unexpected, hold on to this error.
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInternal, err)
	}
	intermediates, err := fulcio.GetIntermediates()
	if err != nil {
		// this is unexpected, hold on to this error.
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInternal, err)
	}

	return &TrustedRoot{
		FulcioRoot:          roots,
		FulcioIntermediates: intermediates,
		RekorPubKeys:        rekorPubKeys,
		CTPubKeys:           ctPubKeys,
	}, nil
}

// Cache the TUF roots to reduce traffic and read contention on the cached file.
var manager atomic.Value

func TrustedRootSingleton(ctx context.Context) (*TrustedRoot, error) {
	root := manager.Load()
	if root != nil {
		return root.(*TrustedRoot), nil
	}
	trustedRoot, err := getTrustedRoot(ctx)
	if err != nil {
		return nil, err
	}

	manager.Store(trustedRoot)
	return trustedRoot, nil
}
