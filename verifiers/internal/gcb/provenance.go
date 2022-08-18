package gcb

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa01 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
	"github.com/slsa-framework/slsa-verifier/verifiers/internal/gcb/keys"
)

var GCBBuilderIDs = []string{"https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2"}

type v01IntotoStatement struct {
	intoto.StatementHeader
	Predicate slsa01.ProvenancePredicate `json:"predicate"`
}

type gloudProvenance struct {
	ImageSummary struct {
		Digest              string `json:"digest"`
		FullQualifiedDigest string `json:"fully_qualified_digest"`
		Registry            string `json:"registry"`
		Repsitory           string `json:"repository"`
	} `json:"image_summary"`
	ProvenanceSummary struct {
		Provenance []struct {
			Build struct {
				// Note: used for testing only. This value is not trusted
				// and should not be used.
				// IntotoStatement v01IntotoStatement `json:"intotoStatement"`
			} `json:"build"`
			Kind        string           `json:"kind"`
			ResourceUri string           `json:"resourceUri"`
			Envelope    dsselib.Envelope `json:"envelope"`
		} `json:"provenance"`
	} `json:"provenance_summary"`
}

type GCBProvenance struct {
	gcloudProv                    *gloudProvenance
	verifiedIntotoStatementStruct *v01IntotoStatement
}

func ProvenanceFromBytes(payload []byte) (*GCBProvenance, error) {
	var prov gloudProvenance
	err := json.Unmarshal(payload, &prov)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal: %w", err)
	}

	return &GCBProvenance{
		gcloudProv: &prov,
	}, nil
}

func signatureAsRaw(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return sig, nil
}

func payloadFromEnvelope(env *dsselib.Envelope) ([]byte, error) {
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return payload, nil
}

func (self *GCBProvenance) isVerified() error {
	// Check that the signature is verified.
	if self.verifiedIntotoStatementStruct == nil {
		return serrors.ErrorNoValidSignature
	}
	return nil
}

func (self *GCBProvenance) GetVerifiedIntotoStatement() ([]byte, error) {
	if err := self.isVerified(); err != nil {
		return nil, err
	}
	d, err := json.Marshal(self.verifiedIntotoStatementStruct)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return d, nil
}

func (self *GCBProvenance) VerifyIntotoHeaders() error {
	if err := self.isVerified(); err != nil {
		return err
	}

	statement := self.verifiedIntotoStatementStruct
	// https://in-toto.io/Statement/v0.1
	if statement.StatementHeader.Type != intoto.StatementInTotoV01 {
		return fmt.Errorf("%w: expected statement header type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, intoto.StatementInTotoV01, statement.StatementHeader.Type)
	}

	// https://slsa.dev/provenance/v0.1
	if statement.StatementHeader.PredicateType != slsa01.PredicateSLSAProvenance {
		return fmt.Errorf("%w: expected statement predicate type '%s', got '%s'",
			serrors.ErrorInvalidDssePayload, slsa01.PredicateSLSAProvenance, statement.StatementHeader.PredicateType)
	}

	return nil
}

func isValidBuilderID(id string) error {
	for _, b := range GCBBuilderIDs {
		if id == b {
			return nil
		}
	}
	return serrors.ErrorMismatchBuilderID
}

func (self *GCBProvenance) VerifyBuilderID(builderOpts *options.BuilderOpts) (string, error) {
	if err := self.isVerified(); err != nil {
		return "", err
	}

	statement := self.verifiedIntotoStatementStruct
	predicateBuilderID := statement.Predicate.Builder.ID

	// Sanity check the builderID.
	if err := isValidBuilderID(predicateBuilderID); err != nil {
		return "", err
	}

	// Validate with user-provided value.
	if builderOpts != nil && builderOpts.ExpectedID != nil {
		if *builderOpts.ExpectedID != predicateBuilderID {
			return "", fmt.Errorf("%w: expected '%s', got '%s'", serrors.ErrorMismatchBuilderID,
				*builderOpts.ExpectedID, predicateBuilderID)
		}
	}

	// Valiate that the recipe type is consistent.
	if predicateBuilderID != statement.Predicate.Recipe.Type {
		return "", fmt.Errorf("%w: expected '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			predicateBuilderID, statement.Predicate.Recipe.Type)
	}

	// Validate the recipe argument type.
	expectedType := "type.googleapis.com/google.devtools.cloudbuild.v1.Build"
	args, ok := statement.Predicate.Recipe.Arguments.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("%w: recipe arguments is not a map", serrors.ErrorInvalidDssePayload)
	}
	ts, err := getAsString(args, "@type")
	if err != nil {
		return "", err
	}

	if ts != expectedType {
		return "", fmt.Errorf("%w: expected '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			expectedType, ts)
	}

	return predicateBuilderID, nil
}

func getAsString(m map[string]interface{}, key string) (string, error) {
	t, ok := m["@type"]
	if !ok {
		return "", fmt.Errorf("%w: '%s' field is absent", serrors.ErrorInvalidDssePayload, key)
	}
	ts, ok := t.(string)
	if !ok {
		return "", fmt.Errorf("%w: '%s' is not a string", serrors.ErrorInvalidDssePayload, key)
	}
	return ts, nil
}

func (self *GCBProvenance) VerifySubjectDigest(expectedHash string) error {
	if err := self.isVerified(); err != nil {
		return err
	}

	statement := self.verifiedIntotoStatementStruct
	for _, subject := range statement.StatementHeader.Subject {
		digestSet := subject.Digest
		hash, exists := digestSet["sha256"]
		if !exists {
			return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no sha256 subject digest")
		}

		if hash == expectedHash {
			return nil
		}
	}

	return fmt.Errorf("expected hash '%s' not found: %w", expectedHash, serrors.ErrorMismatchHash)
}

// Verify source URI in provenance statement.
func (self *GCBProvenance) VerifySourceURI(expectedSourceURI string) error {
	if err := self.isVerified(); err != nil {
		return err
	}

	statement := self.verifiedIntotoStatementStruct
	materials := statement.Predicate.Materials
	if len(materials) == 0 {
		return fmt.Errorf("%w: no materials", serrors.ErrorInvalidDssePayload)
	}
	uri := materials[0].URI
	if !strings.HasPrefix(expectedSourceURI, "https://") {
		expectedSourceURI = "https://" + expectedSourceURI
	}
	if !strings.HasPrefix(uri, expectedSourceURI+"/commit/") {
		return fmt.Errorf("%w: expected '%s', got '%s'",
			serrors.ErrorMismatchSource, expectedSourceURI, uri)
	}

	return nil
}

func (self *GCBProvenance) VerifyBranch(branch string) error {
	return fmt.Errorf("%w: GCB branch verification", serrors.ErrorNotSupported)
}

func (self *GCBProvenance) VerifyTag(tag string) error {
	return fmt.Errorf("%w: GCB tag verification", serrors.ErrorNotSupported)
}

func (self *GCBProvenance) VerifyVersionedTag(tag string) error {
	return fmt.Errorf("%w: GCB versioned-tag verification", serrors.ErrorNotSupported)
}

func (self *GCBProvenance) VerifySignature() error {
	if len(self.gcloudProv.ProvenanceSummary.Provenance) == 0 {
		return fmt.Errorf("%w: no provenance found", serrors.ErrorInvalidDssePayload)
	}
	// Assume a single provenance in the array.
	prov := self.gcloudProv.ProvenanceSummary.Provenance[0]

	// Verify the envelope type. It should be an intoto type.
	if prov.Envelope.PayloadType != intoto.PayloadType {
		return fmt.Errorf("%w: expected payload type '%s', got %s",
			serrors.ErrorInvalidDssePayload, intoto.PayloadType, prov.Envelope.PayloadType)
	}

	payload, err := payloadFromEnvelope(&prov.Envelope)
	if err != nil {
		return err
	}

	payloadHash := sha256.Sum256(payload)

	var errs []error
	regex := regexp.MustCompile(`^projects\/verified-builder\/locations\/(.*)\/keyRings\/attestor\/cryptoKeys\/builtByGCB\/cryptoKeyVersions\/1$`)

	for _, sig := range prov.Envelope.Signatures {
		match := regex.FindStringSubmatch(sig.KeyID)
		if len(match) == 2 {
			// Create a public key instance for this region.
			region := match[1]
			pubKey, err := keys.PublicKeyNew(region)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Decode the signature.
			sig, err := signatureAsRaw(sig.Sig)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			// Verify the signature.
			err = pubKey.VerifySignature(payloadHash, sig)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			var statement v01IntotoStatement
			if err := json.Unmarshal(payload, &statement); err != nil {
				return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
			}
			self.verifiedIntotoStatementStruct = &statement
			fmt.Fprintf(os.Stderr, "Verification succeeded with region key '%s'\n", region)
			return nil
		}
	}

	return fmt.Errorf("%w: %v", serrors.ErrorNoValidSignature, errs)
}
