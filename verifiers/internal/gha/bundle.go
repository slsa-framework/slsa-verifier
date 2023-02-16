package gha

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	bundle_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"google.golang.org/protobuf/encoding/protojson"
)

// Bundle specific errors.
var (
	ErrorMismatchSignature       = errors.New("bundle tlog entry does not match signature")
	ErrorUnexpectedEntryType     = errors.New("unexpected tlog entry type")
	ErrorMissingCertInBundle     = errors.New("missing signing certificate in bundle")
	ErrorUnexpectedBundleContent = errors.New("expected DSSE bundle content")
)

// IsSigstoreBundle checks if the provenance is a Sigstore bundle.
func IsSigstoreBundle(bytes []byte) bool {
	var bundle bundle_v1.Bundle
	if err := protojson.Unmarshal(bytes, &bundle); err != nil {
		return false
	}
	return true
}

// verifyRekorEntryFromBundle extracts and verifies the Rekor entry from the Sigstore
// bundle verification material, validating the SignedEntryTimestamp.
func verifyRekorEntryFromBundle(ctx context.Context, tlogEntry *v1.TransparencyLogEntry,
	trustedRoot *TrustedRoot) (
	*models.LogEntryAnon, error,
) {
	canonicalBody := tlogEntry.GetCanonicalizedBody()
	logID := hex.EncodeToString(tlogEntry.GetLogId().GetKeyId())
	rekorEntry := &models.LogEntryAnon{
		Body:           canonicalBody,
		IntegratedTime: &tlogEntry.IntegratedTime,
		LogIndex:       &tlogEntry.LogIndex,
		LogID:          &logID,
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: tlogEntry.GetInclusionPromise().GetSignedEntryTimestamp(),
		},
	}

	// Verify tlog entry.
	if _, err := verifyTlogEntry(ctx, *rekorEntry, false,
		trustedRoot.RekorPubKeys); err != nil {
		return nil, err
	}

	return rekorEntry, nil
}

// getEnvelopeFromBundle extracts the DSSE envelope from the Sigstore bundle.
func getEnvelopeFromBundle(bundle *bundle_v1.Bundle) (*dsselib.Envelope, error) {
	dsseEnvelope := bundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, ErrorUnexpectedBundleContent
	}
	env := &dsselib.Envelope{
		PayloadType: dsseEnvelope.GetPayloadType(),
		Payload:     base64.StdEncoding.EncodeToString(dsseEnvelope.GetPayload()),
	}
	for _, sig := range dsseEnvelope.GetSignatures() {
		env.Signatures = append(env.Signatures, dsselib.Signature{
			KeyID: sig.GetKeyid(),
			Sig:   base64.StdEncoding.EncodeToString(sig.GetSig()),
		})
	}
	return env, nil
}

// getLeafCertFromBundle extracts the signing cert from the Sigstore bundle.
func getLeafCertFromBundle(bundle *bundle_v1.Bundle) (*x509.Certificate, error) {
	certChain := bundle.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if len(certChain) == 0 {
		return nil, ErrorMissingCertInBundle
	}

	// The first certificate is the leaf cert: see
	// https://github.com/sigstore/protobuf-specs/blob/16541696de137c6281d66d075a4924d9bbd181ff/protos/sigstore_common.proto#L170
	certBytes := certChain[0].GetRawBytes()
	return x509.ParseCertificate(certBytes)
}

// matchRekorEntryWithEnvelope ensures that the log entry references the given
// DSSE envelope. It MUST verify that the signatures match to ensure that the
// tlog timestamp attests to the signature creation time.
func matchRekorEntryWithEnvelope(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	kindVersion := tlogEntry.GetKindVersion()
	if kindVersion.Kind != "intoto" &&
		kindVersion.Version != "0.0.2" {
		return fmt.Errorf("%w: expected intoto:0.0.2, got %s:%s", ErrorUnexpectedEntryType,
			kindVersion.Kind, kindVersion.Version)
	}

	canonicalBody := tlogEntry.GetCanonicalizedBody()
	var toto models.Intoto
	var intotoObj models.IntotoV002Schema
	if err := json.Unmarshal(canonicalBody, &toto); err != nil {
		return fmt.Errorf("%w: %s", ErrorUnexpectedEntryType, err)
	}
	specMarshal, err := json.Marshal(toto.Spec)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrorUnexpectedEntryType, err)
	}
	if err := json.Unmarshal(specMarshal, &intotoObj); err != nil {
		return fmt.Errorf("%w: %s", ErrorUnexpectedEntryType, err)
	}

	if len(env.Signatures) != len(intotoObj.Content.Envelope.Signatures) {
		return fmt.Errorf("expected %d sigs in canonical body, got %d",
			len(env.Signatures),
			len(intotoObj.Content.Envelope.Signatures))
	}

	for _, sig := range env.Signatures {
		// The signature in the canonical body is double base64-encoded.
		encodedEnvSig := base64.StdEncoding.EncodeToString(
			[]byte(sig.Sig))
		var matchCanonical bool
		for _, canonicalSig := range intotoObj.Content.Envelope.Signatures {
			if canonicalSig.Sig.String() == encodedEnvSig {
				matchCanonical = true
			}
		}
		if !matchCanonical {
			return ErrorMismatchSignature
		}
	}
	return nil
}

// VerifyProvenanceBundle verifies the DSSE envelope using the offline Rekor bundle and
// returns the verified DSSE envelope containing the provenance
// and the signing certificate given the provenance.
func VerifyProvenanceBundle(ctx context.Context, bundleBytes []byte,
	trustedRoot *TrustedRoot) (
	*SignedAttestation, error,
) {
	// Extract the SigningCert, Envelope, and RekorEntry from the bundle.
	var bundle bundle_v1.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}

	// We only expect one TLOG entry. If this changes in the future, we must iterate
	// for a matching one.
	if bundle.GetVerificationMaterial() == nil ||
		len(bundle.GetVerificationMaterial().GetTlogEntries()) == 0 {
		return nil, fmt.Errorf("bundle missing offline tlog verification material %d", len(bundle.GetVerificationMaterial().GetTlogEntries()))
	}

	// Verify tlog entry.
	tlogEntry := bundle.GetVerificationMaterial().GetTlogEntries()[0]
	rekorEntry, err := verifyRekorEntryFromBundle(ctx, tlogEntry, trustedRoot)
	if err != nil {
		return nil, err
	}

	// Extract DSSE envelope.
	env, err := getEnvelopeFromBundle(&bundle)
	if err != nil {
		return nil, err
	}

	// Match tlog entry signature with the envelope.
	if err := matchRekorEntryWithEnvelope(tlogEntry, env); err != nil {
		return nil, fmt.Errorf("matching bundle entry with content: %w", err)
	}

	// Get certificate from bundle.
	cert, err := getLeafCertFromBundle(&bundle)
	if err != nil {
		return nil, err
	}

	proposedSignedAtt := &SignedAttestation{
		SigningCert: cert,
		Envelope:    env,
		RekorEntry:  rekorEntry,
	}

	if err := verifySignedAttestation(proposedSignedAtt, trustedRoot); err != nil {
		return nil, err
	}

	return proposedSignedAtt, nil
}

func VerifyNpmPublishBundle(ctx context.Context, bundleBytes []byte,
	trustedRoot *TrustedRoot) (
	*SignedAttestation, error,
) {
	/*
		NOTE: key available at https://registry.npmjs.org/-/npm/v1/keys
			  https://docs.npmjs.com/about-registry-signatures
			{
		  "keys": [
		    {
		      "expires": null,
		      "keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
		      "keytype": "ecdsa-sha2-nistp256",
		      "scheme": "ecdsa-sha2-nistp256",
		      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="
		    }
		  ]
		}
	*/
	//TODO: verify the hash and the pub key match.
	// Extract the Envelope and RekorEntry from the bundle.
	var bundle bundle_v1.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}

	// We only expect one TLOG entry. If this changes in the future, we must iterate
	// for a matching one.
	if bundle.GetVerificationMaterial() == nil ||
		len(bundle.GetVerificationMaterial().GetTlogEntries()) == 0 {
		return nil, fmt.Errorf("bundle missing offline tlog verification material %d", len(bundle.GetVerificationMaterial().GetTlogEntries()))
	}

	// Verify tlog entry.
	tlogEntry := bundle.GetVerificationMaterial().GetTlogEntries()[0]
	rekorEntry, err := verifyRekorEntryFromBundle(ctx, tlogEntry, trustedRoot)
	if err != nil {
		return nil, err
	}

	// Extract DSSE envelope.
	env, err := getEnvelopeFromBundle(&bundle)
	if err != nil {
		return nil, err
	}

	// Match tlog entry signature with the envelope.
	if err := matchRekorEntryWithEnvelope(tlogEntry, env); err != nil {
		return nil, fmt.Errorf("matching bundle entry with content: %w", err)
	}

	// TODO: code above is shared with verifyArtifact, should share it properly

	// TODO: use separate class, possible shared with GCB for key type.
	payload, err := payloadFromEnvelope(env)
	if err != nil {
		return nil, err
	}

	payloadHash := sha256.Sum256(payload)

	// Verify the signatures.
	if len(env.Signatures) == 0 {
		return nil, fmt.Errorf("%w: no signatures found in envelope", serrors.ErrorNoValidSignature)
	}

	// A single signature.
	sig := env.Signatures[0]
	b64key := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="
	rawKey, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		return nil, fmt.Errorf("DecodeString: %w", err)
	}

	key, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key not of type ECDSA", err)
	}

	// TODO: check the keyid to detect key rotation / changes
	rsig, err := decodeSignature(sig.Sig)
	if err != nil {
		return nil, fmt.Errorf("decodeSigature: %w: %s", serrors.ErrorInvalidEncoding, err)
	}

	if ecdsa.VerifyASN1(pubKey, payloadHash[:], rsig) {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, sig.Sig)
	}

	publishSignedAtt := &SignedAttestation{
		Envelope:   env,
		RekorEntry: rekorEntry,
	}

	// if err := verifySignedAttestation(proposedSignedAtt, trustedRoot); err != nil {
	// 	return nil, err
	// }

	return publishSignedAtt, nil
}

// TODO: own file. already used by gcb/provenance.go
func payloadFromEnvelope(env *dsselib.Envelope) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	if payload == nil {
		return nil, fmt.Errorf("%w: empty payload", serrors.ErrorInvalidFormat)
	}
	return payload, nil
}

func decodeSignature(s string) ([]byte, error) {
	var errs []error
	// First try the std decoding.
	rsig, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	// If std decoding failed, try URL decoding.
	// We try both because we encountered decoding failures
	// during our tests. The DSSE documentation does not prescribe
	// which encoding to use: `Either standard or URL-safe encoding is allowed`.
	// https://github.com/secure-systems-lab/dsse/blob/27ce241dec575998dee8967c3c76d4edd5d6ee73/envelope.md#standard-json-envelope.
	rsig, err = base64.URLEncoding.DecodeString(s)
	if err == nil {
		// No error, return the value.
		return rsig, nil
	}
	errs = append(errs, err)

	return nil, fmt.Errorf("%w: %v", serrors.ErrorInvalidEncoding, errs)
}
