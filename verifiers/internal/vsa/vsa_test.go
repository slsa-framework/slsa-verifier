package vsa

import (
	"context"
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts" // Add this import
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
)

const testDir = "./testdata"

func Test_VerifyVSA(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name             string
		attestationPath  string
		vsaOpts          *options.VSAOpts
		verificationOpts *options.VerificationOpts
		err              error
	}{
		{
			"success",
			"gce/v1/gke-gce-pre.bcid-vsa.jsonl",
			&options.VSAOpts{
				ExpectedDigests:        &[]string{"gce_image_id:8970095005306000053"},
				ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
				ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
				ExpectedVerifiedLevels: &[]string{"BCID_L1", "SLSA_BUILD_LEVEL_2"},
			},
			&options.VerificationOpts{
				PublicKey:         mustPublicKey(filepath.Clean(filepath.Join(testDir, "gce/v1/vsa_signing_public_key.pem"))),
				PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			nil,
		},
		{
			"success: unspecified levels",
			"gce/v1/gke-gce-pre.bcid-vsa.jsonl",
			&options.VSAOpts{
				ExpectedDigests:        &[]string{"gce_image_id:8970095005306000053"},
				ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
				ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
				ExpectedVerifiedLevels: &[]string{},
			},
			&options.VerificationOpts{
				PublicKey:         mustPublicKey(filepath.Clean(filepath.Join(testDir, "gce/v1/vsa_signing_public_key.pem"))),
				PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			nil,
		},
		{
			"failure: missing levels",
			"gce/v1/gke-gce-pre.bcid-vsa.jsonl",
			&options.VSAOpts{
				ExpectedDigests:        &[]string{"gce_image_id:8970095005306000053"},
				ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
				ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_3"},
			},
			&options.VerificationOpts{
				PublicKey:         mustPublicKey(filepath.Clean(filepath.Join(testDir, "gce/v1/vsa_signing_public_key.pem"))),
				PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			serrors.ErrorMismatchVerifiedLevels,
		},
		{
			"failure: unspecified subject digests",
			"gce/v1/gke-gce-pre.bcid-vsa.jsonl",
			&options.VSAOpts{
				ExpectedDigests:        &[]string{},
				ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
				ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
				ExpectedVerifiedLevels: &[]string{},
			},
			&options.VerificationOpts{
				PublicKey:         mustPublicKey(filepath.Clean(filepath.Join(testDir, "gce/v1/vsa_signing_public_key.pem"))),
				PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			serrors.ErrorInvalidSubject,
		},
		{
			"failure: mismatch subject digests",
			"gce/v1/gke-gce-pre.bcid-vsa.jsonl",
			&options.VSAOpts{
				ExpectedDigests:        &[]string{"my-giest:123"},
				ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
				ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
				ExpectedVerifiedLevels: &[]string{},
			},
			&options.VerificationOpts{
				PublicKey:         mustPublicKey(filepath.Clean(filepath.Join(testDir, "gce/v1/vsa_signing_public_key.pem"))),
				PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			serrors.ErrorMissingSubjectDigest,
		},
		{
			"failure: mismatch resource URI",
			"gce/v1/gke-gce-pre.bcid-vsa.jsonl",
			&options.VSAOpts{
				ExpectedDigests:        &[]string{"gce_image_id:8970095005306000053"},
				ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
				ExpectedResourceURI:    pointerTo("my-uri://my/path"),
				ExpectedVerifiedLevels: &[]string{},
			},
			&options.VerificationOpts{
				PublicKey:         mustPublicKey(filepath.Clean(filepath.Join(testDir, "gce/v1/vsa_signing_public_key.pem"))),
				PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			serrors.ErrorMismatchResourceURI,
		},
		{
			"failure: msimatch verifier id",
			"gce/v1/gke-gce-pre.bcid-vsa.jsonl",
			&options.VSAOpts{
				ExpectedDigests:        &[]string{"gce_image_id:8970095005306000053"},
				ExpectedVerifierID:     pointerTo("https://celestial-being.gn/gundam"),
				ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
				ExpectedVerifiedLevels: &[]string{},
			},
			&options.VerificationOpts{
				PublicKey:         mustPublicKey(filepath.Clean(filepath.Join(testDir, "gce/v1/vsa_signing_public_key.pem"))),
				PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			serrors.ErrorMismatchVerifierID,
		},
		// TODO: Add more test cases
	}

	for _, tt := range tests {
		// t.Parallel()

		attestationPath := filepath.Clean(filepath.Join(testDir, tt.attestationPath))
		attestation, err := os.ReadFile(attestationPath)
		if err != nil {
			t.Errorf("failed to read attestations file: %v", err)
		}

		_, trustedAttesterID, err := VerifyVSA(ctx, attestation, tt.vsaOpts, tt.verificationOpts)
		if err != nil && trustedAttesterID != nil {
			t.Errorf("unexpected trustedAttesterID to be nil: %v", trustedAttesterID)
		}

		if err == nil {
			if diff := cmp.Diff(*tt.vsaOpts.ExpectedVerifierID, trustedAttesterID.Name()); diff != "" {
				t.Errorf("unexpected trustedAttesterID (-want +got): \n%s", diff)
			}
		}

		if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
			t.Errorf("unexpected error (-want +got): \n%s", diff)
		}
	}
}

func mustPublicKey(path string) crypto.PublicKey {
	pubKeyBytes, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pubKeyBytes)
	if err != nil {
		panic(err)
	}
	return pubKey
}

func pointerTo[K any](object K) *K {
	return &object
}
