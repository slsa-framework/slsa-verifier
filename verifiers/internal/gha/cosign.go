package gha

import (
	"context"
	"fmt"
	"sync"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

var (
	// defaultCosignCheckOpts are the default options for cosign checks.
	defaultCosignCheckOpts *cosign.CheckOpts

	// defaultCosignCheckOptsOnce is used for initializing the defaultCosignCheckOpts.
	defaultCosignCheckOptsOnce = new(sync.Once)
)

// getDefaultCosignCheckOpts returns the default cosign check options.
// This is cached in memory.
// CheckOpts.RegistryClientOpts must be added by the receiver.
func getDefaultCosignCheckOpts(ctx context.Context) (*cosign.CheckOpts, error) {
	var err error
	// Initialize the defaultCosignCheckOpts.
	// defaultCosignCheckOptsOnce is reinitialized upon error.
	defaultCosignCheckOptsOnce.Do(func() {
		rootCerts, err := fulcioroots.Get()
		if err != nil {
			err = fmt.Errorf("%w: %s", serrors.ErrorInternal, err)
			defaultCosignCheckOptsOnce = new(sync.Once)
			return
		}
		intermediateCerts, err := fulcioroots.GetIntermediates()
		if err != nil {
			err = fmt.Errorf("%w: %s", serrors.ErrorInternal, err)
			defaultCosignCheckOptsOnce = new(sync.Once)
			return
		}
		rekorPubKeys, err := cosign.GetRekorPubs(ctx)
		if err != nil {
			err = fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, err)
			defaultCosignCheckOptsOnce = new(sync.Once)
			return
		}
		ctPubKeys, err := cosign.GetCTLogPubs(ctx)
		if err != nil {
			// this is unexpected, hold on to this error.
			err = fmt.Errorf("%w: %s", serrors.ErrorInternal, err)
			defaultCosignCheckOptsOnce = new(sync.Once)
			return
		}

		defaultCosignCheckOpts = &cosign.CheckOpts{
			RootCerts:         rootCerts,
			IntermediateCerts: intermediateCerts,
			RekorPubKeys:      rekorPubKeys,
			CTLogPubKeys:      ctPubKeys,
		}
	})
	if err != nil {
		return nil, err
	}
	return defaultCosignCheckOpts, nil
}
