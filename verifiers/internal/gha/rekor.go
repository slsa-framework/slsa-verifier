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
	"sync"
	"time"

	cjson "github.com/docker/go/canonical/json"
	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/dsse"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/intoto"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	rverify "github.com/sigstore/rekor/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	dsseverifier "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/slsa-framework/slsa-github-generator/signing/envelope"

	rekorClient "github.com/sigstore/rekor/pkg/client"
	sigstoreRoot "github.com/sigstore/sigstore-go/pkg/root"
	sigstoreVerify "github.com/sigstore/sigstore-go/pkg/verify"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

const (
	defaultRekorAddr = "https://rekor.sigstore.dev"
)

var (
	defaultRekorClient     *client.Rekor
	defaultRekorClientOnce = new(sync.Once)
)

// getDefaultRekorClient returns a cached Rekor client.
func getDefaultRekorClient() (*client.Rekor, error) {
	var err error
	defaultRekorClientOnce.Do(func() {
		defaultRekorClient, err = rekorClient.GetRekorClient(defaultRekorAddr)
		if err != nil {
			defaultRekorClientOnce = new(sync.Once)
			return
		}
	})
	if err != nil {
		return nil, err
	}
	return defaultRekorClient, nil
}

func verifyTlogEntryByUUID(ctx context.Context, rekorClient *client.Rekor,
	entryUUID string, trustedRoot *sigstoreRoot.TrustedRoot) (
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
		return verifyTlogEntry(ctx, entry, true, trustedRoot)
	}

	return nil, serrors.ErrorRekorSearch
}

// verifyTlogEntry verifies a Rekor entry content against a trusted Rekor key.
// Verification includes verifying the SignedEntryTimestamp and, if verifyInclusion
// is true, the inclusion proof along with the signed tree head.
func verifyTlogEntry(ctx context.Context, e models.LogEntryAnon,
	verifyInclusion bool, trustedRoot *sigstoreRoot.TrustedRoot) (
	*models.LogEntryAnon, error,
) {
	// get the public key from sigstore-go
	rekorLogsMap := trustedRoot.RekorLogs()
	keyID := *e.LogID
	rekorLog, ok := rekorLogsMap[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, "Rekor log ID not found in trusted root")
	}
	pubKey, ok := rekorLog.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, "rekor public key is not an ECDSA key")
	}

	// Verify the root hash against the current Signed Entry Tree Head
	verifier, err := signature.LoadECDSAVerifier(pubKey,
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
	case *intoto_v001.V001Entry:
		publicKeyB64, err = e.IntotoObj.PublicKey.MarshalText()
	case *dsse_v001.V001Entry:
		if len(e.DSSEObj.Signatures) > 1 {
			return nil, errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		publicKeyB64, err = e.DSSEObj.Signatures[0].Verifier.MarshalText()
	default:
		return nil, errors.New("unexpected tlog entry type")
	}
	if err != nil {
		return nil, err
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

func intotoEntry(certPem, provenance []byte) (models.ProposedEntry, error) {
	if len(certPem) == 0 {
		return nil, fmt.Errorf("no signing certificate found in intoto envelope")
	}
	var pubKeyBytes [][]byte
	pubKeyBytes = append(pubKeyBytes, certPem)

	return types.NewProposedEntry(context.Background(), intoto.KIND, intoto_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  provenance,
		PublicKeyBytes: pubKeyBytes,
	})
}

func dsseEntry(certPem, provenance []byte) (models.ProposedEntry, error) {
	if len(certPem) == 0 {
		return nil, fmt.Errorf("no signing certificate found in intoto envelope")
	}

	var pubKeyBytes [][]byte
	pubKeyBytes = append(pubKeyBytes, certPem)

	return types.NewProposedEntry(context.Background(), dsse.KIND, dsse_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  provenance,
		PublicKeyBytes: pubKeyBytes,
	})
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
	provenance []byte, trustedRoot *sigstoreRoot.TrustedRoot,
) (*SignedAttestation, error) {
	// Use intoto attestation to find rekor entry UUIDs.
	params := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	if err != nil {
		return nil, fmt.Errorf("error getting certificate from provenance: %w", err)
	}

	intotoEntry, err := intotoEntry(certPem, provenance)
	if err != nil {
		return nil, fmt.Errorf("error creating intoto entry: %w", err)
	}
	dsseEntry, err := dsseEntry(certPem, provenance)
	if err != nil {
		return nil, err
	}
	searchLogQuery.SetEntries([]models.ProposedEntry{intotoEntry, dsseEntry})

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
			trustedRoot); err != nil {
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
	rClient *client.Rekor, trustedRoot *sigstoreRoot.TrustedRoot,
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
func verifySignedAttestation(signedAtt *SignedAttestation, trustedRoot *sigstoreRoot.TrustedRoot) error {
	cert := signedAtt.SigningCert
	attBytes, err := cjson.MarshalCanonical(signedAtt.Envelope)
	if err != nil {
		return err
	}
	signatureTimestamp := time.Unix(*signedAtt.RekorEntry.IntegratedTime, 0)

	// Verify the certificate chain, and that the certificate was valid at the time of signing.
	if err := sigstoreVerify.VerifyLeafCertificate(signatureTimestamp, *cert, trustedRoot); err != nil {
		fmt.Fprintf(os.Stderr, "error verifying leaf certificate with sisgtore-go: %v\n", err)
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, err)
	}

	// Verify signature using validated certificate.
	verifier, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	verifier = dsseverifier.WrapVerifier(verifier)
	if err := verifier.VerifySignature(bytes.NewReader(attBytes), bytes.NewReader(attBytes)); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, err)
	}
	return nil
}
