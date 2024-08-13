package gha

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	rekorpbv1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"

	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

func Test_verifyBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	trustedRoot, err := utils.GetSigstoreTrustedRoot()
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

func Test_matchRekorEntryWithEnvelope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tlog *rekorpbv1.TransparencyLogEntry
		env  *dsselib.Envelope
		err  error
	}{
		{
			name: "success: dsse v0.0.1",
			tlog: &rekorpbv1.TransparencyLogEntry{
				KindVersion: &rekorpbv1.KindVersion{
					Kind:    "dsse",
					Version: "0.0.1",
				},
				CanonicalizedBody: []byte(`
				{
					"apiVersion": "0.0.1",
					"kind": "dsse",
					"spec": {
						"signatures": [
							{
								"signature": "MEUCIHiah7zQLL9LK9m9/0JH3rHIaYlvcus4h84KOdaR3iAlAiEAio+tnbpkW+V+FPYxpuiJBY0MuD43RVX5QmMwk3sgnUE="
							}
						]
					}
				}
			`),
			},
			env: &dsselib.Envelope{
				Signatures: []dsselib.Signature{
					{
						Sig: "MEUCIHiah7zQLL9LK9m9/0JH3rHIaYlvcus4h84KOdaR3iAlAiEAio+tnbpkW+V+FPYxpuiJBY0MuD43RVX5QmMwk3sgnUE=",
					},
				},
			},
			err: nil,
		},
		{
			name: "success: intoto v0.0.2",
			tlog: &rekorpbv1.TransparencyLogEntry{
				KindVersion: &rekorpbv1.KindVersion{
					Kind:    "intoto",
					Version: "0.0.2",
				},
				CanonicalizedBody: []byte(`
					{
						"apiVersion": "0.0.2",
						"kind": "intoto",
						"spec": {
							"content": {
								"envelope": {
									"signatures": [
										{
											"publicKey": "mypubkey",
											"sig": "TUVVQ0lRRGVoVlQ0MFRLUDNxWnlVN3BDcXhwMzRyeGt1Wk1ZRTVBWGhBb0x4NTdzdmdJZ0xSa3NCV1hPamUyMCtrKzh4M3ViZkZzNlpxQ2dLNXc3eXlITFB6SC9tcGs9"
										}
									]
								}
							}
						}
					}
				`),
			},
			env: &dsselib.Envelope{
				Signatures: []dsselib.Signature{
					{
						Sig: "MEUCIQDehVT40TKP3qZyU7pCqxp34rxkuZMYE5AXhAoLx57svgIgLRksBWXOje20+k+8x3ubfFs6ZqCgK5w7yyHLPzH/mpk=",
					},
				},
			},
			err: nil,
		},
		{
			name: "faiulure: dsse v0.0.1: mismatch signatures",
			tlog: &rekorpbv1.TransparencyLogEntry{
				KindVersion: &rekorpbv1.KindVersion{
					Kind:    "dsse",
					Version: "0.0.1",
				},
				CanonicalizedBody: []byte(`
				{
					"apiVersion": "0.0.1",
					"kind": "dsse",
					"spec": {
						"signatures": [
							{
								"signature": "MEUCIHiah7zQLL9LK9m9/0JH3rHIaYlvcus4h84KOdaR3iAlAiEAio+tnbpkW+V+FPYxpuiJBY0MuD43RVX5QmMwk3sgnUE="
							}
						]
					}
				}
			`),
			},
			env: &dsselib.Envelope{
				Signatures: []dsselib.Signature{
					{
						Sig: "d3Jvbmcgc2lnCg==",
					},
				},
			},
			err: ErrorMismatchSignature,
		},
		{
			name: "faiulure: intoto v0.0.2: mismatch signatures",
			tlog: &rekorpbv1.TransparencyLogEntry{
				KindVersion: &rekorpbv1.KindVersion{
					Kind:    "intoto",
					Version: "0.0.2",
				},
				CanonicalizedBody: []byte(`
					{
						"apiVersion": "0.0.2",
						"kind": "intoto",
						"spec": {
							"content": {
								"envelope": {
									"signatures": [
										{
											"publicKey": "mypubkey",
											"sig": "TUVVQ0lRRGVoVlQ0MFRLUDNxWnlVN3BDcXhwMzRyeGt1Wk1ZRTVBWGhBb0x4NTdzdmdJZ0xSa3NCV1hPamUyMCtrKzh4M3ViZkZzNlpxQ2dLNXc3eXlITFB6SC9tcGs9"
										}
									]
								}
							}
						}
					}
				`),
			},
			env: &dsselib.Envelope{
				Signatures: []dsselib.Signature{
					{
						Sig: "d3Jvbmcgc2lnCg==",
					},
				},
			},
			err: ErrorMismatchSignature,
		},
		{
			name: "failure: unknown type",
			tlog: &rekorpbv1.TransparencyLogEntry{
				KindVersion: &rekorpbv1.KindVersion{
					Kind:    "slsa",
					Version: "0.0.x",
				},
			},
			env: &dsselib.Envelope{},
			err: ErrorUnexpectedEntryType,
		},
		{
			name: "failure: unknown dsse type version",
			tlog: &rekorpbv1.TransparencyLogEntry{
				KindVersion: &rekorpbv1.KindVersion{
					Kind:    "dsse",
					Version: "0.0.x",
				},
			},
			env: &dsselib.Envelope{},
			err: ErrorUnexpectedEntryType,
		},
		{
			name: "failure: unknown intoto type  version",
			tlog: &rekorpbv1.TransparencyLogEntry{
				KindVersion: &rekorpbv1.KindVersion{
					Kind:    "dsse",
					Version: "0.0.x",
				},
			},
			env: &dsselib.Envelope{},
			err: ErrorUnexpectedEntryType,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := matchRekorEntryWithEnvelope(tt.tlog, tt.env)

			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
		})
	}
}
