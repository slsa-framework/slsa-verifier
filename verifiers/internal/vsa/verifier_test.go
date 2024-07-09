package vsa

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	intotoAttestations "github.com/in-toto/attestation/go/v1"
	intotoGolang "github.com/in-toto/in-toto-golang/in_toto"
	intotoCommon "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/common"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/cryptoutils"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	vsa10 "github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/vsa/v1.0"
)

func Test_extractSignedVSA(t *testing.T) {
	ctx := context.Background()

	t.Parallel()

	goodAttestationString := `
		{
			"_type": "https://in-toto.io/Statement/v1",
			"predicateType": "https://slsa.dev/verification_summary/v1",
			"predicate": {
				"timeVerified": "2024-06-12T07:24:34.351608Z",
				"verifier": {
					"id": "https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"
				},
				"verificationResult": "PASSED",
				"verifiedLevels": [
					"BCID_L1",
					"SLSA_BUILD_LEVEL_2"
				],
				"resourceUri": "gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre",
				"policy": {
					"uri": "googlefile:/google_src/files/642513192/depot/google3/production/security/bcid/software/gce_image/gke/vm_images.sw_policy.textproto"
				}
			},
			"subject": [
				{
				"name": "_",
					"digest": {
						"gce_image_id": "8970095005306000053"
					}
				}
			]
		}
	`
	goodEnvelope := &dsse.Envelope{
		PayloadType: intotoGolang.PayloadType,
		Payload:     mustEncodeAttestationString(goodAttestationString),
		Signatures: []dsse.Signature{
			{
				KeyID: "keystore://76574:prod:vsa_signing_public_key",
				Sig:   "bmIy2gfnQt6oYpd0WbpQMtZcMRtmntDmyki+Be+2Z9qkboMVbi2RQAD1b5AWbBs7iAP8NZVJOI4R/4jOVYB/FA==",
			},
		},
	}
	goodVSAOpts := &options.VerificationOpts{
		PublicKey: mustPublicKeyFromBytes([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeGa6ZCZn0q6WpaUwJrSk+PPYEsca
3Xkk3UrxvbQtoZzTmq0zIYq+4QQl0YBedSyy+XcwAMaUWTouTrB05WhYtg==
-----END PUBLIC KEY-----`)),
		PublicKeyID:       pointerTo("keystore://76574:prod:vsa_signing_public_key"),
		PublicKeyHashAlgo: crypto.SHA256,
	}
	goodVSA := &vsa10.VSA{
		StatementHeader: intotoGolang.StatementHeader{
			Type:          intotoAttestations.StatementTypeUri,
			PredicateType: vsa10.PredicateType,
			Subject: []intotoGolang.Subject{
				{
					Name: "_",
					Digest: map[string]string{
						"gce_image_id": "8970095005306000053",
					},
				},
			},
		},
		Predicate: vsa10.Predicate{
			TimeVerified: time.Date(2024, 6, 12, 7, 24, 34, 351608000, time.UTC),
			Verifier: vsa10.Verifier{
				ID: "https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1",
			},
			ResourceURI: "gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre",
			Policy: intotoCommon.ProvenanceMaterial{
				URI: "googlefile:/google_src/files/642513192/depot/google3/production/security/bcid/software/gce_image/gke/vm_images.sw_policy.textproto",
			},
			VerificationResult: "PASSED",
			VerifiedLevels:     []string{"BCID_L1", "SLSA_BUILD_LEVEL_2"},
		},
	}

	tests := []struct {
		name        string
		envelope    *dsse.Envelope
		opts        *options.VerificationOpts
		expectedVSA *vsa10.VSA
		err         error
	}{
		{
			name:        "success",
			envelope:    goodEnvelope,
			opts:        goodVSAOpts,
			expectedVSA: goodVSA,
		},
		{
			name: "success: sha256 key id in envelope",
			envelope: &dsse.Envelope{
				PayloadType: goodEnvelope.PayloadType,
				Payload:     goodEnvelope.Payload,
				Signatures: []dsse.Signature{
					{
						KeyID: "SHA256:Zphi7kubaI7RnOrkqPgkRdVhF5a2JOFB4gor/Zajiiw",
						Sig:   goodEnvelope.Signatures[0].Sig,
					},
				},
			},
			opts: &options.VerificationOpts{
				PublicKey:         goodVSAOpts.PublicKey,
				PublicKeyID:       pointerTo(""),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			expectedVSA: goodVSA,
		},
		{
			name: "success: no key ids",
			envelope: &dsse.Envelope{
				PayloadType: goodEnvelope.PayloadType,
				Payload:     goodEnvelope.Payload,
				Signatures: []dsse.Signature{
					{
						KeyID: "",
						Sig:   goodEnvelope.Signatures[0].Sig,
					},
				},
			},
			opts: &options.VerificationOpts{
				PublicKey:         goodVSAOpts.PublicKey,
				PublicKeyID:       pointerTo(""),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			expectedVSA: goodVSA,
		},
		{
			name: "success: keyid only in opts",
			envelope: &dsse.Envelope{
				PayloadType: goodEnvelope.PayloadType,
				Payload:     goodEnvelope.Payload,
				Signatures: []dsse.Signature{
					{
						KeyID: "",
						Sig:   goodEnvelope.Signatures[0].Sig,
					},
				},
			},
			opts: &options.VerificationOpts{
				PublicKey:         goodVSAOpts.PublicKey,
				PublicKeyID:       pointerTo("SHA256:Zphi7kubaI7RnOrkqPgkRdVhF5a2JOFB4gor/Zajiiw"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			expectedVSA: goodVSA,
		},
		{
			name: "failure: empty signatures",
			envelope: &dsse.Envelope{
				PayloadType: goodEnvelope.PayloadType,
				Payload:     goodEnvelope.Payload,
				Signatures:  []dsse.Signature{},
			},
			opts:        goodVSAOpts,
			expectedVSA: nil,
			err:         dsse.ErrNoSignature,
		},
		{
			name: "failure: mismatch signature",
			envelope: &dsse.Envelope{
				PayloadType: goodEnvelope.PayloadType,
				Payload:     mustEncodeAttestationString("{}"),
				Signatures:  goodEnvelope.Signatures,
			},
			opts:        goodVSAOpts,
			expectedVSA: nil,
			err:         serrors.ErrorNoValidSignature,
		},
		{
			name:     "failure: misatch keyID",
			envelope: goodEnvelope,
			opts: &options.VerificationOpts{
				PublicKey:         goodVSAOpts.PublicKey,
				PublicKeyID:       pointerTo("keystore://76574:prod:another_key_id"),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			expectedVSA: nil,
			err:         serrors.ErrorNoValidSignature,
		},
		{
			name:     "failure: missing needed keyID",
			envelope: goodEnvelope,
			opts: &options.VerificationOpts{
				PublicKey:         goodVSAOpts.PublicKey,
				PublicKeyID:       pointerTo(""),
				PublicKeyHashAlgo: crypto.SHA256,
			},
			expectedVSA: nil,
			err:         serrors.ErrorNoValidSignature,
		},
		{
			name:     "failure: incorrect algorithm",
			envelope: goodEnvelope,
			opts: &options.VerificationOpts{
				PublicKey:         goodVSAOpts.PublicKey,
				PublicKeyID:       pointerTo(""),
				PublicKeyHashAlgo: crypto.SHA512,
			},
			expectedVSA: nil,
			err:         serrors.ErrorNoValidSignature,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			vsa, err := extractSignedVSA(ctx, tc.envelope, tc.opts)

			if diff := cmp.Diff(tc.expectedVSA, vsa, cmpopts.EquateComparable()); diff != "" {
				t.Errorf("unexpected VSA (-want +got): \n%s", diff)
			}

			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_matchExpectedValues(t *testing.T) {
	t.Parallel()

	goodVSA := &vsa10.VSA{
		StatementHeader: intotoGolang.StatementHeader{
			PredicateType: vsa10.PredicateType,
			Subject: []intotoGolang.Subject{
				{
					Digest: map[string]string{
						"gce_image_id": "8970095005306000053",
						"sha256":       "abc",
					},
				},
			},
		},
		Predicate: vsa10.Predicate{
			Verifier: vsa10.Verifier{
				ID: "https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1",
			},
			ResourceURI:        "gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre",
			VerificationResult: "PASSED",
			VerifiedLevels:     []string{"BCID_L1", "SLSA_BUILD_LEVEL_2"},
		},
	}
	goodVSAOpts := &options.VSAOpts{
		ExpectedDigests:        &[]string{"gce_image_id:8970095005306000053", "sha256:abc"},
		ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1"),
		ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-12615-gke1418000-cos-101-17162-463-29-c-cgpv1-pre"),
		ExpectedVerifiedLevels: &[]string{"BCID_L1", "SLSA_BUILD_LEVEL_2"},
	}

	tests := []struct {
		name string
		vsa  *vsa10.VSA
		opts *options.VSAOpts
		err  error
	}{
		// success cases
		{
			name: "success",
			vsa:  goodVSA,
			opts: goodVSAOpts,
		},
		{
			name: "success: empty verifiedLevels",
			vsa: &vsa10.VSA{
				StatementHeader: goodVSA.StatementHeader,
				Predicate: vsa10.Predicate{
					Verifier:           goodVSA.Predicate.Verifier,
					ResourceURI:        goodVSA.Predicate.ResourceURI,
					VerificationResult: goodVSA.Predicate.VerificationResult,
					VerifiedLevels:     []string{},
				},
			},
			opts: &options.VSAOpts{
				ExpectedDigests:        goodVSAOpts.ExpectedDigests,
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: &[]string{},
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
		},
		{
			name: "success: unspecified verifiedLevels",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        goodVSAOpts.ExpectedDigests,
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: &[]string{},
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
		},
		{
			name: "success: expected lower SLSA level",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        goodVSAOpts.ExpectedDigests,
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_1"},
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
		},
		// failure cases
		{
			name: "expected higher SLSA level",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        goodVSAOpts.ExpectedDigests,
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_3"},
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
			err: serrors.ErrorMismatchVerifiedLevels,
		},
		{
			name: "failure empty digests",
			vsa: &vsa10.VSA{
				StatementHeader: intotoGolang.StatementHeader{
					PredicateType: vsa10.PredicateType,
					Subject: []intotoGolang.Subject{
						{
							Digest: map[string]string{},
						},
					},
				},
				Predicate: goodVSA.Predicate,
			},
			opts: goodVSAOpts,
			err:  serrors.ErrorInvalidDssePayload,
		},
		{
			name: "failure: no supplied digests",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        &[]string{},
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: goodVSAOpts.ExpectedVerifiedLevels,
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
			err: serrors.ErrorEmptyRequiredField,
		},
		{
			name: "failure: missing digest",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        &[]string{"zeit:geist"},
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: goodVSAOpts.ExpectedVerifiedLevels,
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
			err: serrors.ErrorMissingSubjectDigest,
		},
		{
			name: "failure: empty verifierID",
			vsa: &vsa10.VSA{
				StatementHeader: goodVSA.StatementHeader,
				Predicate: vsa10.Predicate{
					Verifier:           vsa10.Verifier{},
					ResourceURI:        goodVSA.Predicate.ResourceURI,
					VerificationResult: goodVSA.Predicate.VerificationResult,
					VerifiedLevels:     goodVSA.Predicate.VerifiedLevels,
				},
			},
			opts: goodVSAOpts,
			err:  serrors.ErrorEmptyRequiredField,
		},
		{
			name: "failure: mismatch verifierID",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        goodVSAOpts.ExpectedDigests,
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: goodVSAOpts.ExpectedVerifiedLevels,
				ExpectedVerifierID:     pointerTo("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.2"),
			},
			err: serrors.ErrorMismatchVerifierID,
		},
		{
			name: "failure: empty resourceURI",
			vsa: &vsa10.VSA{
				StatementHeader: goodVSA.StatementHeader,
				Predicate: vsa10.Predicate{
					Verifier:           goodVSA.Predicate.Verifier,
					ResourceURI:        "",
					VerificationResult: goodVSA.Predicate.VerificationResult,
					VerifiedLevels:     goodVSA.Predicate.VerifiedLevels,
				},
			},
			opts: goodVSAOpts,
			err:  serrors.ErrorEmptyRequiredField,
		},
		{
			name: "failure: mismatch resourceURI",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        goodVSAOpts.ExpectedDigests,
				ExpectedResourceURI:    pointerTo("gce_image://gke-node-images:gke-126GGG"),
				ExpectedVerifiedLevels: goodVSAOpts.ExpectedVerifiedLevels,
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
			err: serrors.ErrorMismatchResourceURI,
		},
		{
			name: "failure: empty verificationResult",
			vsa: &vsa10.VSA{
				StatementHeader: goodVSA.StatementHeader,
				Predicate: vsa10.Predicate{
					Verifier:           goodVSA.Predicate.Verifier,
					ResourceURI:        goodVSA.Predicate.ResourceURI,
					VerificationResult: "",
					VerifiedLevels:     goodVSA.Predicate.VerifiedLevels,
				},
			},
			opts: goodVSAOpts,
			err:  serrors.ErrorInvalidVerificationResult,
		},
		{
			name: "failure: wrong verificationResult",
			vsa: &vsa10.VSA{
				StatementHeader: goodVSA.StatementHeader,
				Predicate: vsa10.Predicate{
					Verifier:           goodVSA.Predicate.Verifier,
					ResourceURI:        goodVSA.Predicate.ResourceURI,
					VerificationResult: "FAILED",
					VerifiedLevels:     goodVSA.Predicate.VerifiedLevels,
				},
			},
			opts: goodVSAOpts,
			err:  serrors.ErrorInvalidVerificationResult,
		},
		{
			name: "failure: missing verifiedLevels",
			vsa:  goodVSA,
			opts: &options.VSAOpts{
				ExpectedDigests:        goodVSAOpts.ExpectedDigests,
				ExpectedResourceURI:    goodVSAOpts.ExpectedResourceURI,
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_3"},
				ExpectedVerifierID:     goodVSAOpts.ExpectedVerifierID,
			},
			err: serrors.ErrorMismatchVerifiedLevels,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := matchExpectedValues(tc.vsa, tc.opts)
			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_matchVerifiedLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		vsa     *vsa10.VSA
		vsaOpts *options.VSAOpts
		err     error
	}{
		// success cases
		{
			name: "success: equal levels",
			vsa: &vsa10.VSA{
				Predicate: vsa10.Predicate{
					VerifiedLevels: []string{"SLSA_BUILD_LEVEL_1", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
				},
			},
			vsaOpts: &options.VSAOpts{
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_1", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
			},
		},
		{
			name: "success: expected lower SLSA level",
			vsa: &vsa10.VSA{
				Predicate: vsa10.Predicate{
					VerifiedLevels: []string{"SLSA_BUILD_LEVEL_1", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
				},
			},
			vsaOpts: &options.VSAOpts{
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_0", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
			},
		},
		{
			name: "success: unspecified verifiedLevels",
			vsa: &vsa10.VSA{
				Predicate: vsa10.Predicate{
					VerifiedLevels: []string{"SLSA_BUILD_LEVEL_1", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
				},
			},
			vsaOpts: &options.VSAOpts{
				ExpectedVerifiedLevels: &[]string{},
			},
		},
		{
			name: "success: no SLSA levels",
			vsa: &vsa10.VSA{
				Predicate: vsa10.Predicate{
					VerifiedLevels: []string{"BCID_L1"},
				},
			},
			vsaOpts: &options.VSAOpts{
				ExpectedVerifiedLevels: &[]string{},
			},
		},
		// failure cases
		{
			name: "failure: expected higher SLSA level",
			vsa: &vsa10.VSA{
				Predicate: vsa10.Predicate{
					VerifiedLevels: []string{"SLSA_BUILD_LEVEL_1", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
				},
			},
			vsaOpts: &options.VSAOpts{
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
			},
			err: serrors.ErrorMismatchVerifiedLevels,
		},
		{
			name: "failure: missing a expected SLSA track",
			vsa: &vsa10.VSA{
				Predicate: vsa10.Predicate{
					VerifiedLevels: []string{"SLSA_BUILD_LEVEL_2", "BCID_L1"},
				},
			},
			vsaOpts: &options.VSAOpts{
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_2", "SLSA_SOURCE_LEVEL_2", "BCID_L1"},
			},
			err: serrors.ErrorMismatchVerifiedLevels,
		},
		{
			name: "failure: missing a expected non-SLSA track",
			vsa: &vsa10.VSA{
				Predicate: vsa10.Predicate{
					VerifiedLevels: []string{"SLSA_BUILD_LEVEL_2"},
				},
			},
			vsaOpts: &options.VSAOpts{
				ExpectedVerifiedLevels: &[]string{"SLSA_BUILD_LEVEL_2", "BCID_L1"},
			},
			err: serrors.ErrorMismatchVerifiedLevels,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := matchVerifiedLevels(tc.vsa, tc.vsaOpts)

			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func Test_extractSLSALevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		levels *[]string
		want   map[string]int
		err    error
	}{
		{
			name: "success",
			levels: &[]string{
				"SLSA_BUILD_LEVEL_1",
				"SLSA_SOURCE_LEVEL_2",
			},
			want: map[string]int{
				"BUILD":  1,
				"SOURCE": 2,
			},
		},
		{
			name:   "success: empty",
			levels: &[]string{},
			want:   map[string]int{},
		},
		{
			name: "failure: invalid level number",
			levels: &[]string{
				"SLSA_BUILD_LEVEL_X",
			},
			err: serrors.ErrorInvalidSLSALevel,
		},
		{
			name: "failure: invalid level text",
			levels: &[]string{
				"SLSA_BUILD_L_1",
			},
			err: serrors.ErrorInvalidSLSALevel,
		},
		{
			name: "failure: no level number",
			levels: &[]string{
				"SLSA_BUILD_LEVEL_",
			},
			err: serrors.ErrorInvalidSLSALevel,
		},
		{
			name: "failure: no last underscore",
			levels: &[]string{
				"SLSA_BUILD_LEVEL",
			},
			err: serrors.ErrorInvalidSLSALevel,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := extractSLSALevels(tc.levels)

			if diff := cmp.Diff(tc.want, got, cmpopts.EquateComparable()); diff != "" {
				t.Errorf("unexpected VSA (-want +got): \n%s", diff)
			}

			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
		})
	}
}

func mustEncodeAttestationString(attestationString string) string {
	dst := &bytes.Buffer{}
	if err := json.Compact(dst, []byte(attestationString)); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(dst.Bytes())
}

func mustPublicKeyFromBytes(pubKeyBytes []byte) crypto.PublicKey {
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pubKeyBytes)
	if err != nil {
		panic(err)
	}
	return pubKey
}

func pointerTo[K any](object K) *K {
	return &object
}
