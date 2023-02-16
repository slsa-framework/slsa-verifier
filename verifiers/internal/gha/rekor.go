package gha

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	cjson "github.com/docker/go/canonical/json"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	intotod "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	rverify "github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/slsa-framework/slsa-github-generator/signing/envelope"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

const (
	defaultRekorAddr = "https://rekor.sigstore.dev"
)

func verifyTlogEntryByUUID(ctx context.Context, rekorClient *client.Rekor,
	entryUUID string, trustedRoot *TrustedRoot) (
	*models.LogEntryAnon, error,
) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.EntryUUID = entryUUID

	lep, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}

	if len(lep.Payload) != 1 {
		return nil, errors.New("UUID value can not be extracted")
	}

	uuid, err := sharding.GetUUIDFromIDString(params.EntryUUID)
	if err != nil {
		return nil, err
	}

	for k, entry := range lep.Payload {
		returnUUID, err := sharding.GetUUIDFromIDString(k)
		if err != nil {
			return nil, err
		}
		// Validate that the request matches the response
		if returnUUID != uuid {
			return nil, errors.New("expected matching UUID")
		}
		// Validate the entry response.
		return verifyTlogEntry(ctx, entry, true, trustedRoot.RekorPubKeys)
	}

	return nil, serrors.ErrorRekorSearch
}

// verifyTlogEntry verifies a Rekor entry content against a trusted Rekor key.
// Verification includes verifying the SignedEntryTimestamp and, if verifyInclusion
// is true, the inclusion proof along with the signed tree head.
func verifyTlogEntry(ctx context.Context, e models.LogEntryAnon,
	verifyInclusion bool, rekorKeys *cosign.TrustedTransparencyLogPubKeys) (
	*models.LogEntryAnon, error,
) {
	// Verify the root hash against the current Signed Entry Tree Head
	verifier, err := signature.LoadECDSAVerifier(rekorKeys.Keys[*e.LogID].PubKey.(*ecdsa.PublicKey),
		crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, err)
	}

	if verifyInclusion {
		// This function verifies the inclusion proof, the signature on the root hash of the
		// inclusion proof, and the SignedEntryTimestamp.
		err = rverify.VerifyLogEntry(ctx, &e, verifier)
	} else {
		// This function verifies the SignedEntryTimestamp
		err = rverify.VerifySignedEntryTimestamp(ctx, &e, verifier)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidRekorEntry, err)
	}

	return &e, nil
}

func extractCert(e *models.LogEntryAnon) (*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *intotod.V001Entry:
		publicKeyB64, err = e.IntotoObj.PublicKey.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) != 1 {
		return nil, errors.New("unexpected number of cert pem tlog entry")
	}

	return certs[0], err
}

func intotoEntry(certPem, provenance []byte) (*intotod.V001Entry, error) {
	if len(certPem) == 0 {
		return nil, fmt.Errorf("no signing certificate found in intoto envelope")
	}
	cert := strfmt.Base64(certPem)
	return &intotod.V001Entry{
		IntotoObj: models.IntotoV001Schema{
			Content: &models.IntotoV001SchemaContent{
				Envelope: string(provenance),
			},
			PublicKey: &cert,
		},
	}, nil
}

// getUUIDsByArtifactDigest finds all entry UUIDs by the digest of the artifact binary.
func getUUIDsByArtifactDigest(rClient *client.Rekor, artifactHash string) ([]string, error) {
	// Use search index to find rekor entry UUIDs that match Subject Digest.
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{Hash: fmt.Sprintf("sha256:%v", artifactHash)}
	resp, err := rClient.Index.SearchIndex(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorSearch, err.Error())
	}

	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("%w: no matching entries found", serrors.ErrorRekorSearch)
	}

	return resp.GetPayload(), nil
}

// GetValidSignedAttestationWithCert finds and validates the matching entry UUIDs with
// the full intoto attestation.
// The attestation generated by the slsa-github-generator libraries contain a signing certificate.
func GetValidSignedAttestationWithCert(rClient *client.Rekor,
	provenance []byte, trustedRoot *TrustedRoot,
) (*SignedAttestation, error) {
	// Use intoto attestation to find rekor entry UUIDs.
	params := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	if err != nil {
		return nil, fmt.Errorf("error getting certificate from provenance: %w", err)
	}

	e, err := intotoEntry(certPem, provenance)
	if err != nil {
		return nil, fmt.Errorf("error creating intoto entry: %w", err)
	}
	entry := models.Intoto{
		APIVersion: swag.String(e.APIVersion()),
		Spec:       e.IntotoObj,
	}
	searchLogQuery.SetEntries([]models.ProposedEntry{&entry})

	params.SetEntry(&searchLogQuery)
	resp, err := rClient.Entries.SearchLogQuery(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorSearch, err.Error())
	}

	if len(resp.GetPayload()) != 1 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorSearch, "no matching rekor entries")
	}

	logEntry := resp.Payload[0]
	var rekorEntry models.LogEntryAnon
	for uuid, e := range logEntry {
		if _, err := verifyTlogEntry(context.Background(), e, true,
			trustedRoot.RekorPubKeys); err != nil {
			return nil, fmt.Errorf("error verifying tlog entry: %w", err)
		}
		rekorEntry = e
		url := fmt.Sprintf("%v/%v/%v", defaultRekorAddr, "api/v1/log/entries", uuid)
		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at URL: %s\n", *e.LogIndex, url)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(certPem)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("error unmarshaling certificate from pem")
	}

	env, err := EnvelopeFromBytes(provenance)
	if err != nil {
		return nil, err
	}

	proposedSignedAtt := &SignedAttestation{
		SigningCert: certs[0],
		Envelope:    env,
		RekorEntry:  &rekorEntry,
	}

	if err := verifySignedAttestation(proposedSignedAtt, trustedRoot); err != nil {
		return nil, err
	}

	return proposedSignedAtt, nil
}

// SearchValidSignedAttestation searches for a valid signing certificate using the Rekor
// Redis search index by using the artifact digest.
func SearchValidSignedAttestation(ctx context.Context, artifactHash string, provenance []byte,
	rClient *client.Rekor, trustedRoot *TrustedRoot,
) (*SignedAttestation, error) {
	// Get Rekor UUIDs by artifact digest.
	uuids, err := getUUIDsByArtifactDigest(rClient, artifactHash)
	if err != nil {
		return nil, err
	}

	env, err := EnvelopeFromBytes(provenance)
	if err != nil {
		return nil, err
	}

	// Iterate through each matching UUID and perform:
	//   * Verify TLOG entry (inclusion and signed entry timestamp against Rekor pubkey).
	//   * Verify the signing certificate against the Fulcio root CA.
	//   * Verify dsse envelope signature against signing certificate.
	//   * Check signature expiration against IntegratedTime in entry.
	//   * If all succeed, return the signing certificate.
	var errs []string
	for _, uuid := range uuids {
		entry, err := verifyTlogEntryByUUID(ctx, rClient, uuid, trustedRoot)
		if err != nil {
			// this is unexpected, hold on to this error.
			errs = append(errs, fmt.Sprintf("%s: verifying tlog entry %s", err, uuid))
			continue
		}

		cert, err := extractCert(entry)
		if err != nil {
			// this is unexpected, hold on to this error.
			errs = append(errs, fmt.Sprintf("%s: extracting certificate from %s", err, uuid))
			continue
		}

		proposedSignedAtt := &SignedAttestation{
			Envelope:    env,
			SigningCert: cert,
			RekorEntry:  entry,
		}

		err = verifySignedAttestation(proposedSignedAtt, trustedRoot)
		if errors.Is(err, serrors.ErrorInternal) {
			// Return on an internal error
			return nil, err
		} else if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		// success!
		url := fmt.Sprintf("%v/%v/%v", defaultRekorAddr, "api/v1/log/entries", uuid)
		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at URL: %s\n", *entry.LogIndex, url)
		return proposedSignedAtt, nil
	}

	return nil, fmt.Errorf("%w: got unexpected errors %s", serrors.ErrorNoValidRekorEntries, strings.Join(errs, ", "))
}

// verifyAttestationSignature validates the signature on the attestation
// given a certificate and a validated signature time from a verified
// Rekor entry.
// The certificate is verified up to Fulcio, the signature is validated
// using the certificate, and the signature generation time is checked
// to be within the certificate validity period.
func verifySignedAttestation(signedAtt *SignedAttestation, trustedRoot *TrustedRoot) error {
	cert := signedAtt.SigningCert
	attBytes, err := cjson.MarshalCanonical(signedAtt.Envelope)
	if err != nil {
		return err
	}
	signatureTimestamp := time.Unix(*signedAtt.RekorEntry.IntegratedTime, 0)

	// 1. Verify certificate chain.
	co := &cosign.CheckOpts{
		RootCerts:         trustedRoot.FulcioRoot,
		IntermediateCerts: trustedRoot.FulcioIntermediates,
		Identities: []cosign.Identity{
			{
				Issuer:        certOidcIssuer,
				SubjectRegExp: certSubjectRegexp,
			},
		},
		CTLogPubKeys: trustedRoot.CTPubKeys,
	}
	verifier, err := cosign.ValidateAndUnpackCert(signedAtt.SigningCert, co)
	if err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, err)
	}

	// 2. Verify signature using validated certificate.
	verifier = dsse.WrapVerifier(verifier)
	if err := verifier.VerifySignature(bytes.NewReader(attBytes), bytes.NewReader(attBytes)); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, err)
	}

	// 3. Verify signature was creating during certificate validity period.
	if err := cosign.CheckExpiry(cert, signatureTimestamp); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, err)
	}
	return nil
}
