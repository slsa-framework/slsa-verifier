//go:build regression

package verifiers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"testing"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
)

const TEST_DIR = "../cli/slsa-verifier/testdata"

// Test_VerifyNpmPackage ensures that verifiers.VerifyNpmPackage works,
// borrowing only a few examples from the larger set of cases in main.Test_runVerifyGHAArtifactPath
func Test_VerifyNpmPackage(t *testing.T) {
	// We cannot use t.Setenv due to parallelized tests.
	os.Setenv("SLSA_VERIFIER_EXPERIMENTAL", "1")
	t.Parallel()

	tests := []struct {
		name       string
		artifact   string
		builderID  string
		source     string
		pkgVersion string
		pkgName    string
		err        error
	}{
		{
			name:       "valid npm CLI builder",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggles",
			pkgVersion: "1.0.5",
			pkgName:    "@trishankatdatadog/supreme-goggles",
			builderID:  "https://github.com/actions/runner/github-hosted",
		},
		{
			name:       "valid npm CLI builder mismatch source",
			artifact:   "supreme-googles-cli-v02-tag.tgz",
			source:     "github.com/trishankatdatadog/supreme-goggleS",
			pkgVersion: "1.0.5",
			pkgName:    "@trishankatdatadog/supreme-goggles",
			builderID:  "https://github.com/actions/runner/github-hosted",
			err:        serrors.ErrorMismatchSource,
		},
		{
			name:      "invalid signature provenance npm CLI",
			artifact:  "supreme-googles-cli-v02-tag-invalidsigprov.tgz",
			source:    "github.com/trishankatdatadog/supreme-goggles",
			pkgName:   "@trishankatdatadog/supreme-goggles",
			builderID: "https://github.com/actions/runner/github-hosted",
			err:       serrors.ErrorInvalidSignature,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			artifactPath := filepath.Clean(filepath.Join(TEST_DIR, "npm", "gha", tt.artifact))
			attestationsPath := fmt.Sprintf("%s.json", artifactPath)
			artifactHash, err := computeFileHash(artifactPath, sha256.New())
			if err != nil {
				t.Fatal(err)
			}
			attestations, err := os.ReadFile(attestationsPath)
			if err != nil {
				t.Fatal(err)
			}
			provenanceOpts := &options.ProvenanceOpts{
				ExpectedSourceURI:      tt.source,
				ExpectedDigest:         artifactHash,
				ExpectedPackageName:    &tt.pkgName,
				ExpectedPackageVersion: &tt.pkgVersion,
			}
			builderOpts := &options.BuilderOpts{
				ExpectedID: &tt.builderID,
			}
			VerifyNpmPackage(context.Background(), attestations, artifactHash, provenanceOpts, builderOpts)
		})
	}
}

func computeFileHash(filePath string, h hash.Hash) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
