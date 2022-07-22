package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

var errInvalid = errors.New("invalid")

type v1Query struct {
	Source         string            `json:"source"`
	Tag            string            `json:"tag"`
	VersionedTag   string            `json:"versionedTag"`
	ArtifactHash   string            `json:"artifactHash"`
	DsseEnvelope   *dsselib.Envelope `json:"provenanceContent"`
	showProvenance bool              `json:"showProvenance"`
}

type validation string

var (
	validationSuccess = validation("success")
	validationFailure = validation("failure")
)

type v1Result struct {
	Error           *string                     `json:"error,omitempty"`
	Validation      validation                  `json:"validation"`
	IntotoStatement *intoto.ProvenanceStatement `json:"provenanceContent,omitempty"`
}

func VerifyHandlerV1(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		http.Error(w, "empty request", http.StatusInternalServerError)
		return
	}

	results := verifyHandlerV1(r)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// w.WriteHeader(http.StatusOK)
}

func toStringPtr(e error) *string {
	if e != nil {
		s := e.Error()
		return &s
	}
	return nil
}

func v1ResultNew() *v1Result {
	return &v1Result{
		Error:           nil,
		Validation:      validationFailure,
		IntotoStatement: nil,
	}
}

func (r *v1Result) withError(e error) *v1Result {
	r.Error = toStringPtr(e)
	return r
}

func (r *v1Result) withValidation(v validation) *v1Result {
	r.Validation = v
	return r
}

func verifyHandlerV1(r *http.Request) *v1Result {
	results := v1ResultNew()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return results.withError(err)
	}
	r.Body.Close()

	// Create a query.
	query, err := queryFromString(body)
	if err != nil {
		return results.withError(err)
	}

	// Validate it.
	if err := query.validate(); err != nil {
		return results.withError(err)
	}

	// Run the verification.

	if query.showProvenance {
	}

	// TODO:Write the response.
	return results.withValidation(validationSuccess)
}

func queryFromString(content []byte) (*v1Query, error) {
	var query v1Query
	err := json.Unmarshal(content, &query)
	if err != nil {
		return nil, err
	}
	return &query, nil
}

func (q *v1Query) validate() error {
	if q.Source == "" {
		return fmt.Errorf("%w: empty source", errInvalid)
	}

	if q.ArtifactHash == "" {
		return fmt.Errorf("%w: empty artifactHash", errInvalid)
	}

	if q.DsseEnvelope == nil {
		return fmt.Errorf("%w: empty dsseEnvelope", errInvalid)
	}

	if q.Tag != "" && q.VersionedTag != "" {
		return fmt.Errorf("%w: tag and versionedTag are mutually exclusive", errInvalid)
	}

	return nil
}
