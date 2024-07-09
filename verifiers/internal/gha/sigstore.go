package gha

import (
	"context"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
)

func verifySigstoreBundle(ctx context.Context, provenanceBytes []byte) (*SignedAttestation, error) {
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, err
	}

	verifier, err := verify.NewSignedEntityVerifier(
		trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, err
	}

	certID, err := verify.NewShortCertificateIdentity(
		"https://token.actions.githubusercontent.com",
		"",
		"",
		"^https://github.com/sigstore/sigstore-js/",
	)
	if err != nil {
		return nil, err
	}

	policy := verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(certID))

	bundle, err := loadBundleFromBytes(provenanceBytes)
	if err != nil {
		return nil, err
	}

	_, err = verifier.Verify(bundle, policy)
	if err != nil {
		return nil, err
	}

	return getSignedAttestationFromSigstoreBundle(ctx, bundle)
}

func loadBundleFromBytes(provenanceBytes []byte) (*bundle.ProtobufBundle, error) {
	var bundle bundle.ProtobufBundle
	bundle.Bundle = new(protobundle.Bundle)
	err := bundle.UnmarshalJSON(provenanceBytes)
	if err != nil {
		return nil, err
	}
	return &bundle, nil
}

func getSignedAttestationFromSigstoreBundle(ctx context.Context, bundle *bundle.ProtobufBundle) (*SignedAttestation, error) {
	envelope, err := getEnvelopeFromBundle(bundle.Bundle)
	if err != nil {
		return nil, err
	}

	cert, err := getLeafCertFromBundle(bundle.Bundle)
	if err != nil {
		return nil, err
	}

	publicKey := bundle.GetVerificationMaterial().GetPublicKey()

	signedAttestation := &SignedAttestation{
		Envelope:    envelope,
		SigningCert: cert,
		// RekorEntry: nil, // no need to set this field, if we're not directly using rekor
		PublicKey: publicKey,
	}
	return signedAttestation, nil
}
