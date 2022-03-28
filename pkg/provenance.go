package pkg

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cjson "github.com/docker/go/canonical/json"
	"github.com/go-openapi/runtime"
	"github.com/google/trillian/merkle/logverifier"
	"github.com/google/trillian/merkle/rfc6962"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/client/tlog"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	intotod "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/sigstore/rekor/pkg/util"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	defaultRekorAddr = "https://rekor.sigstore.dev"
	certOidcIssuer   = "https://token.actions.githubusercontent.com"
	// TODO: Make this into a list.
	trustedReusableWorkflow = "gossts/slsa-go/.github/workflows/builder.yml"
)

var (
	errorInvalidDssePayload = errors.New("invalid DSSE envelope payload")
	errorRekorSearch        = errors.New("error searching rekor entries")
	errorMismatchHash       = errors.New("binary artifact hash does not match provenance subject")
)

func EnvelopeFromBytes(payload []byte) (env *dsselib.Envelope, err error) {
	env = &dsselib.Envelope{}
	err = json.Unmarshal(payload, env)
	return
}

// Get SHA256 Subject Digest from the provenance statement.
func getSha256Digest(env *dsselib.Envelope) (string, error) {
	pyld, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", fmt.Errorf("%w: %s", errorInvalidDssePayload, "decoding payload")
	}
	prov := &intoto.ProvenanceStatement{}
	if err := json.Unmarshal([]byte(pyld), prov); err != nil {
		return "", fmt.Errorf("%w: %s", errorInvalidDssePayload, "unmarshalling json")
	}
	if len(prov.Subject) == 0 {
		return "", fmt.Errorf("%w: %s", errorInvalidDssePayload, "no subjects")
	}
	digestSet := prov.Subject[0].Digest
	hash, exists := digestSet["sha256"]
	if !exists {
		return "", fmt.Errorf("%w: %s", errorInvalidDssePayload, "no sha256 subject digest")
	}
	return hash, nil
}

// GetRekorEntries finds all entry UUIDs by the digest of the artifact binary.
func GetRekorEntries(rClient *client.Rekor, artifactHash string) ([]string, error) {
	// Use search index to find rekor entry UUIDs that match Subject Digest.
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{Hash: fmt.Sprintf("sha256:%v", artifactHash)}
	resp, err := rClient.Index.SearchIndex(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errorRekorSearch, err.Error())
	}

	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("%w: no matching entries found", errorRekorSearch)
	}

	return resp.GetPayload(), nil
}

func verifyRootHash(ctx context.Context, rekorClient *client.Rekor, proof *models.InclusionProof, pub *ecdsa.PublicKey) error {
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

	rootHash, err := hex.DecodeString(*proof.RootHash)
	if err != nil {
		return errors.New("error decoding root hash in inclusion proof")
	}

	if *proof.TreeSize == int64(sth.Size) {
		if !bytes.Equal(rootHash, sth.Hash) {
			return errors.New("root hash returned from server does not match inclusion proof hash")
		}
	} else if *proof.TreeSize < int64(sth.Size) {
		consistencyParams := tlog.NewGetLogProofParamsWithContext(ctx)
		consistencyParams.FirstSize = proof.TreeSize // Root hash at the time the proof was returned
		consistencyParams.LastSize = int64(sth.Size) // Root hash verified with rekor pubkey

		consistencyProof, err := rekorClient.Tlog.GetLogProof(consistencyParams)
		if err != nil {
			return err
		}
		hashes := [][]byte{}
		for _, h := range consistencyProof.Payload.Hashes {
			b, err := hex.DecodeString(h)
			if err != nil {
				return errors.New("error decoding consistency proof hashes")
			}
			hashes = append(hashes, b)
		}
		v := logverifier.New(rfc6962.DefaultHasher)
		if err := v.VerifyConsistencyProof(*proof.TreeSize, int64(sth.Size), rootHash, sth.Hash, hashes); err != nil {
			return err
		}
	} else if *proof.TreeSize > int64(sth.Size) {
		return errors.New("inclusion proof returned a tree size larger than the verified tree size")
	}
	return nil
}

func verifyTlogEntry(ctx context.Context, rekorClient *client.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.EntryUUID = uuid

	lep, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}

	if len(lep.Payload) != 1 {
		return nil, errors.New("UUID value can not be extracted")
	}
	e := lep.Payload[params.EntryUUID]
	if e.Verification == nil || e.Verification.InclusionProof == nil {
		return nil, errors.New("inclusion proof not provided")
	}

	hashes := [][]byte{}
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
	leafHash, err := hex.DecodeString(params.EntryUUID)
	if err != nil {
		return nil, errors.New("error decoding hex encoded leaf hash")
	}

	// Verify the root hash against the current Signed Entry Tree Head
	pubs, err := cosign.GetRekorPubs(ctx)
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
		return nil, fmt.Errorf("%w: %s", err, "error verifying root hash")
	}

	// Verify the entry's inclusion
	v := logverifier.New(rfc6962.DefaultHasher)
	if err := v.VerifyInclusionProof(*e.Verification.InclusionProof.LogIndex, *e.Verification.InclusionProof.TreeSize, hashes, rootHash, leafHash); err != nil {
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
		setVerError = cosign.VerifySET(payload, []byte(e.Verification.SignedEntryTimestamp), pubKey.PubKey)
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
	for _, uuid := range uuids {
		entry, err := verifyTlogEntry(ctx, rClient, uuid)
		if err != nil {
			fmt.Printf(err.Error())
			continue
		}
		cert, err := extractCert(entry)
		if err != nil {
			continue
		}

		co := &cosign.CheckOpts{
			RootCerts:      fulcio.GetRoots(),
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
		// success!
		fmt.Printf("Verified against tlog entry %d\n", *entry.LogIndex)
		return cert, nil
	}

	return nil, errors.New("could not find a matching signature entry")
}

func getExtension(cert *x509.Certificate, oid string) string {
	for _, ext := range cert.Extensions {
		if strings.Contains(ext.Id.String(), oid) {
			return string(ext.Value)
		}
	}
	return ""
}

type WorkflowIdentity struct {
	// The caller repository
	CallerRepository string `json:"caller"`
	// The commit SHA where the workflow was triggered
	CallerHash string `json:"commit"`
	// Current workflow (reuseable workflow) ref
	JobWobWorkflowRef string `json:"job_workflow_ref"`
	// Trigger
	Trigger string `json:"trigger"`
	// Issuer
	Issuer string `json:"issuer"`
}

// GetWorkflowFromCertificate gets the workflow identity from the Fulcio authenticated content.
func GetWorkflowInfoFromCertificate(cert *x509.Certificate) (*WorkflowIdentity, error) {
	if len(cert.URIs) == 0 {
		return nil, errors.New("missing URI information from certificate")
	}

	return &WorkflowIdentity{
		CallerRepository:  getExtension(cert, "1.3.6.1.4.1.57264.1.5"),
		Issuer:            getExtension(cert, "1.3.6.1.4.1.57264.1.1"),
		Trigger:           getExtension(cert, "1.3.6.1.4.1.57264.1.2"),
		CallerHash:        getExtension(cert, "1.3.6.1.4.1.57264.1.3"),
		JobWobWorkflowRef: cert.URIs[0].Path,
	}, nil
}

// VerifyWorkflowIdentity verifies the signing certificate information
func VerifyWorkflowIdentity(id *WorkflowIdentity, source string) error {
	// cert URI path is /org/repo/path/to/workflow@ref
	workflowPath := strings.SplitN(id.JobWobWorkflowRef, "@", 2)
	if len(workflowPath) < 2 {
		return errors.New("malformed URI for workflow")
	}

	if !strings.EqualFold(strings.Trim(workflowPath[0], "/"), trustedReusableWorkflow) {
		return errors.New("untrusted reuseable workflow")
	}

	if !strings.EqualFold(id.Issuer, certOidcIssuer) {
		return errors.New("untrusted token issuer")
	}

	// The caller repository in the x509 extension is not fully qualified. It only contains
	// {org}/{repository}.
	if !strings.EqualFold(id.CallerRepository, strings.TrimPrefix(source, "github.com/")) {
		return fmt.Errorf("unexpected caller repository, got '%s'", id.CallerRepository)
	}

	return nil
}

func VerifyProvenance(env *dsselib.Envelope, expectedHash string) error {
	hash, err := getSha256Digest(env)
	if err != nil {
		return err
	}

	if !strings.EqualFold(hash, expectedHash) {
		return errorMismatchHash
	}

	return nil
}
