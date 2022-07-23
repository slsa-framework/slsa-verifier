package verification

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	cjson "github.com/docker/go/canonical/json"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/google/trillian/merkle/rfc6962"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	intotod "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/slsa-framework/slsa-github-generator/signing/envelope"
	"github.com/transparency-dev/merkle/proof"
)

const (
	defaultRekorAddr = "https://rekor.sigstore.dev"
)

func verifyRootHash(ctx context.Context, rekorClient *client.Rekor, eproof *models.InclusionProof, pub *ecdsa.PublicKey) error {
	infoParams := tlog.NewGetLogInfoParamsWithContext(ctx)
	result, err := rekorClient.Tlog.GetLogInfo(infoParams)
	if err != nil {
		return err
	}

	logInfo := result.GetPayload()

	sth := util.SignedCheckpoint{}
	if err := sth.UnmarshalText([]byte(*logInfo.SignedTreeHead)); err != nil {
		return err
	}

	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return err
	}

	if !sth.Verify(verifier) {
		return errors.New("signature on tree head did not verify")
	}

	rootHash, err := hex.DecodeString(*eproof.RootHash)
	if err != nil {
		return errors.New("error decoding root hash in inclusion proof")
	}

	if *eproof.TreeSize == int64(sth.Size) {
		if !bytes.Equal(rootHash, sth.Hash) {
			return errors.New("root hash returned from server does not match inclusion proof hash")
		}
	} else if *eproof.TreeSize < int64(sth.Size) {
		consistencyParams := tlog.NewGetLogProofParamsWithContext(ctx)
		consistencyParams.FirstSize = eproof.TreeSize // Root hash at the time the proof was returned
		consistencyParams.LastSize = int64(sth.Size)  // Root hash verified with rekor pubkey

		consistencyProof, err := rekorClient.Tlog.GetLogProof(consistencyParams)
		if err != nil {
			return err
		}
		var hashes [][]byte
		for _, h := range consistencyProof.Payload.Hashes {
			b, err := hex.DecodeString(h)
			if err != nil {
				return errors.New("error decoding consistency proof hashes")
			}
			hashes = append(hashes, b)
		}
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher,
			uint64(*eproof.TreeSize), sth.Size, hashes, rootHash, sth.Hash); err != nil {
			return err
		}
	} else if *eproof.TreeSize > int64(sth.Size) {
		return errors.New("inclusion proof returned a tree size larger than the verified tree size")
	}
	return nil
}

func verifyTlogEntryByUUID(ctx context.Context, rekorClient *client.Rekor, entryUUID string) (*models.LogEntryAnon, error) {
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

	var e models.LogEntryAnon
	for k, entry := range lep.Payload {
		if k != uuid {
			return nil, errors.New("expected matching UUID")
		}
		e = entry
	}

	return verifyTlogEntry(ctx, rekorClient, uuid, e)
}

func verifyTlogEntry(ctx context.Context, rekorClient *client.Rekor, uuid string, e models.LogEntryAnon) (*models.LogEntryAnon, error) {
	if e.Verification == nil || e.Verification.InclusionProof == nil {
		return nil, errors.New("inclusion proof not provided")
	}

	var hashes [][]byte
	for _, h := range e.Verification.InclusionProof.Hashes {
		hb, err := hex.DecodeString(h)
		if err != nil {
			return nil, errors.New("error decoding inclusion proof hashes")
		}
		hashes = append(hashes, hb)
	}

	rootHash, err := hex.DecodeString(*e.Verification.InclusionProof.RootHash)
	if err != nil {
		return nil, errors.New("error decoding hex encoded root hash")
	}
	leafHash, err := hex.DecodeString(uuid)
	if err != nil {
		return nil, errors.New("error decoding hex encoded leaf hash")
	}

	// Verify the root hash against the current Signed Entry Tree Head
	pubs, err := cosign.GetRekorPubs(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, "unable to fetch Rekor public keys from TUF repository")
	}

	var entryVerError error
	for _, pubKey := range pubs {
		// Verify inclusion against the signed tree head
		entryVerError = verifyRootHash(ctx, rekorClient, e.Verification.InclusionProof, pubKey.PubKey)
		if entryVerError == nil {
			break
		}
	}
	if entryVerError != nil {
		return nil, fmt.Errorf("%w: %s", entryVerError, "error verifying root hash")
	}

	// Verify the entry's inclusion
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher,
		uint64(*e.Verification.InclusionProof.LogIndex),
		uint64(*e.Verification.InclusionProof.TreeSize), leafHash, hashes, rootHash); err != nil {
		return nil, fmt.Errorf("%w: %s", err, "verifying inclusion proof")
	}

	// Verify rekor's signature over the SET.
	payload := bundle.RekorPayload{
		Body:           e.Body,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       *e.LogIndex,
		LogID:          *e.LogID,
	}

	var setVerError error
	for _, pubKey := range pubs {
		setVerError = cosign.VerifySET(payload, e.Verification.SignedEntryTimestamp, pubKey.PubKey)
		// Return once the SET is verified successfully.
		if setVerError == nil {
			break
		}
	}

	return &e, setVerError
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

	eimpl, err := types.NewEntry(pe)
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

func intotoEntry(certPem []byte, provenance []byte) (*intotod.V001Entry, error) {
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

// GetRekorEntries finds all entry UUIDs by the digest of the artifact binary.
func GetRekorEntries(rClient *client.Rekor, artifactHash string) ([]string, error) {
	// Use search index to find rekor entry UUIDs that match Subject Digest.
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{Hash: fmt.Sprintf("sha256:%v", artifactHash)}
	resp, err := rClient.Index.SearchIndex(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrorRekorSearch, err.Error())
	}

	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("%w: no matching entries found", ErrorRekorSearch)
	}

	return resp.GetPayload(), nil
}

// GetRekorEntriesWithCert finds all entry UUIDs with the full intoto attestation.
// The attestation generated by the slsa-github-generator libraries contain a signing certificate.
func GetRekorEntriesWithCert(rClient *client.Rekor, provenance []byte) (*dsselib.Envelope, *x509.Certificate, error) {
	// Use intoto attestation to find rekor entry UUIDs.
	params := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting certificate from provenance: %w", err)
	}

	e, err := intotoEntry(certPem, provenance)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating intoto entry: %w", err)
	}
	entry := models.Intoto{
		APIVersion: swag.String(e.APIVersion()),
		Spec:       e.IntotoObj,
	}
	entries := []models.ProposedEntry{&entry}
	searchLogQuery.SetEntries(entries)

	params.SetEntry(&searchLogQuery)
	resp, err := rClient.Entries.SearchLogQuery(params)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrorRekorSearch, err.Error())
	}

	if len(resp.GetPayload()) != 1 {
		return nil, nil, fmt.Errorf("%w: %s", ErrorRekorSearch, "no matching rekor entries")
	}

	logEntry := resp.Payload[0]
	for uuid, e := range logEntry {
		if _, err := verifyTlogEntry(context.Background(), rClient, uuid, e); err != nil {
			return nil, nil, fmt.Errorf("error verifying tlog entry: %w", err)
		}
		url := fmt.Sprintf("%v/%v/%v", defaultRekorAddr, "api/v1/log/entries", uuid)
		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at URL: %s\n", *e.LogIndex, url)
	}

	env, err := EnvelopeFromBytes(provenance)
	if err != nil {
		return nil, nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(certPem)
	if err != nil {
		return nil, nil, err
	}
	if len(certs) != 1 {
		return nil, nil, fmt.Errorf("error unmarshaling certificate from pem")
	}

	return env, certs[0], nil
}

// FindSigningCertificate finds and verifies a matching signing certificate from a list of Rekor entry UUIDs.
func FindSigningCertificate(ctx context.Context, uuids []string, dssePayload dsselib.Envelope, rClient *client.Rekor) (*x509.Certificate, error) {
	attBytes, err := cjson.MarshalCanonical(dssePayload)
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
		entry, err := verifyTlogEntryByUUID(ctx, rClient, uuid)
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

		roots, err := fulcio.GetRoots()
		if err != nil {
			// this is unexpected, hold on to this error.
			errs = append(errs, fmt.Sprintf("%s: retrieving fulcio root", err))
			continue
		}
		co := &cosign.CheckOpts{
			RootCerts:      roots,
			CertOidcIssuer: certOidcIssuer,
		}
		verifier, err := cosign.ValidateAndUnpackCert(cert, co)
		if err != nil {
			continue
		}
		verifier = dsse.WrapVerifier(verifier)
		if err := verifier.VerifySignature(bytes.NewReader(attBytes), bytes.NewReader(attBytes)); err != nil {
			continue
		}
		it := time.Unix(*entry.IntegratedTime, 0)
		if err := cosign.CheckExpiry(cert, it); err != nil {
			continue
		}
		uuid, err := cosign.ComputeLeafHash(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error computing leaf hash for tlog entry at index: %d\n", *entry.LogIndex)
			continue
		}

		// success!
		url := fmt.Sprintf("%v/%v/%v", defaultRekorAddr, "api/v1/log/entries", hex.EncodeToString(uuid))
		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at URL: %s\n", *entry.LogIndex, url)
		return cert, nil
	}

	return nil, fmt.Errorf("%w: got unexpected errors %s", ErrorNoValidRekorEntries, strings.Join(errs, ", "))
}
