package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/slsa-framework/slsa-verifier/cmd"
	"github.com/slsa-framework/slsa-verifier/verification"
)

var errInvalid = errors.New("invalid")

type v1Query struct {
	// Compulsory fields.
	Source       string `json:"source"`
	ArtifactHash string `json:"artifactHash"`
	DsseEnvelope string `json:"provenanceContent"`
	// Optional fields.
	Tag             *string `json:"tag"`
	Branch          *string `json:"branch"`
	VersionedTag    *string `json:"versionedTag"`
	PrintProvenance *bool   `json:"printProvenance"`
}

type validation string

var (
	validationSuccess = validation("success")
	validationFailure = validation("failure")
)

type v1Result struct {
	Error           *string    `json:"error,omitempty"`
	Validation      validation `json:"validation"`
	IntotoStatement *string    `json:"provenanceContent,omitempty"`
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

func (r *v1Result) withIntotoStatement(c []byte) *v1Result {
	b := base64.StdEncoding.EncodeToString(c)
	r.IntotoStatement = &b
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
	branch := "main"
	if query.Branch != nil {
		branch = *query.Branch
	}
	provenanceOpts := &verification.ProvenanceOpts{
		ExpectedBranch:       branch,
		ExpectedDigest:       query.ArtifactHash,
		ExpectedVersionedTag: query.VersionedTag,
		ExpectedTag:          query.Tag,
	}

	ctx := context.Background()
	p, err := cmd.Verify(ctx, []byte(query.DsseEnvelope),
		query.ArtifactHash, query.Source, provenanceOpts)
	if err != nil {
		return results.withError(err)
	}

	if query.PrintProvenance != nil && *query.PrintProvenance {
		results = results.withIntotoStatement(p)
	}

	return results.withValidation(validationSuccess)
}

func queryFromString(content []byte) (*v1Query, error) {
	var query v1Query
	err := json.Unmarshal(content, &query)
	if err != nil {
		return nil, err
	}

	env, err := base64.StdEncoding.DecodeString(query.DsseEnvelope)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding payload", errInvalid)
	}
	query.DsseEnvelope = string(env)
	return &query, nil
}

func (q *v1Query) validate() error {
	if q.Source == "" {
		return fmt.Errorf("%w: empty source", errInvalid)
	}

	if q.ArtifactHash == "" {
		return fmt.Errorf("%w: empty artifactHash", errInvalid)
	}

	if q.DsseEnvelope == "" {
		return fmt.Errorf("%w: empty dsseEnvelope", errInvalid)
	}

	if q.Tag != nil && q.VersionedTag != nil {
		return fmt.Errorf("%w: tag and versionedTag are mutually exclusive", errInvalid)
	}

	return nil
}
