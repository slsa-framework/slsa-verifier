package gha

import (
	"context"
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
)

// verifyRekorEntryFromBundle extracts the Rekor entry from the Sigstore bundle verification material.
func verifyRekorEntryFromBundle(ctx context.Context, tlogEntry *v1.TransparencyLogEntry) (
	*models.LogEntryAnon, error) {
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
	if _, err := verifyTlogEntry(ctx, *rekorEntry, false); err != nil {
		return nil, err
	}

	return rekorEntry, nil
}

// getEnvelopeFromBundle extracts the DSSE envelope from the Sigstore bundle.
func getEnvelopeFromBundle(bundle *bundle_v1.Bundle) (*dsselib.Envelope, error) {
	dsseEnvelope := bundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, errors.New("bundle does not sign over a DSSE envelope")
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

// getCertFromBundle extracts the signing cert from the Sigstore bundle.
func getCertFromBundle(bundle *bundle_v1.Bundle) (*x509.Certificate, error) {
	certChain := bundle.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if len(certChain) == 0 {
		return nil, errors.New("missing signing certificate in bundle")
	}
	certBytes := certChain[0].GetRawBytes()
	return x509.ParseCertificate(certBytes)
}

// matchRekorEntryWithEnvelope ensures that the log entry references the given
// DSSE envelope. It MUST verify that the signatures match to ensure that the
// tlog timestamp attests to the signature creation time.
func matchRekorEntryWithEnvelope(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	if tlogEntry.GetKindVersion().Kind != "intoto" &&
		tlogEntry.GetKindVersion().Version != "0.0.2" {
		return errors.New("unexpected canonical entry kind and version, expected intoto:0.0.2")
	}

	canonicalBody := tlogEntry.GetCanonicalizedBody()
	var toto models.Intoto
	var intotoObj models.IntotoV002Schema
	if err := json.Unmarshal(canonicalBody, &toto); err != nil {
		return err
	}
	specMarshal, err := json.Marshal(toto.Spec)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(specMarshal, &intotoObj); err != nil {
		return err
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
		if matchCanonical != true {
			return errors.New("could not find envelope signature in canonical rekor entry")
		}
	}
	return nil
}
