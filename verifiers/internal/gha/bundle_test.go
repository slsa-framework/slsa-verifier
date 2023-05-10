package gha

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func Test_verifyBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := TrustedRootSingleton(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		path     string
		expected error
	}{
		{
			name: "valid bundle",
			path: "./testdata/bundle/valid.intoto.sigstore",
		},
		{
			name:     "mismatch rekor entry",
			path:     "./testdata/bundle/mismatch-tlog.intoto.sigstore",
			expected: ErrorMismatchSignature,
		},

		{
			name:     "invalid Rekor SET",
			path:     "./testdata/bundle/invalid-set.intoto.sigstore",
			expected: serrors.ErrorInvalidRekorEntry,
		},
		/* we hit the SET error before we can hit the invalid DSSE sig
		{
		name: "invalid DSSE sig",
		path: "./testdata/bundle/invalid-dsse-sig.intoto.sigstore",
		},
		{
			name: "invalid expiry with Rekor timestamp",
			path: "./testdata/bundle/invalid-expiry-tlog.intoto.sigstore",
		},
		{
			name: "invalid no DSSE",
			path: "./testdata/bundle/invalid-no-dsse.intoto.sigstore",
		},
		{
			name: "invalid no certificate",
			path: "./testdata/bundle/invalid-no-cert.intoto.sigstore",
		},
		*/
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			_, err = VerifyProvenanceBundle(ctx, content, trustedRoot)

			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}
