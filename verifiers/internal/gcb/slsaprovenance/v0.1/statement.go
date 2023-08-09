package v01

// NOTE: Copy of github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1
// This holds an internal copy of in-toto-golang's structs for
// SLSA predicates to handle GCB's incompatibility with the
// published specification.
// Specifically, GCB provenance currently produces a string for
// ProvenancePredicate.Recipe.DefinedInMaterial rather than the SLSA compliant
// signed integer. Because of this, we comment out the field and do not unmarshal
// this in the Go struct. When comparing the envelope with the human-readable
// content, this field is ignored!
// GCB will later add compliant fields in the signed envelope, but NOT in the
// human-readable component. Either disregard comparison between human-readable
// summary and the signed envelope, or use this struct in comparison.

import (
	"encoding/json"
	"fmt"
	"time"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/common"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gcb/slsaprovenance/iface"
)

const (
	// PredicateSLSAProvenance represents a build provenance for an artifact.
	PredicateSLSAProvenance = "https://slsa.dev/provenance/v0.1"
)

// ProvenancePredicate is the provenance predicate definition.
type ProvenancePredicate struct {
	Builder   ProvenanceBuilder    `json:"builder"`
	Recipe    ProvenanceRecipe     `json:"recipe"`
	Metadata  *ProvenanceMetadata  `json:"metadata,omitempty"`
	Materials []ProvenanceMaterial `json:"materials,omitempty"`
}

// ProvenanceBuilder idenfifies the entity that executed the build steps.
type ProvenanceBuilder struct {
	ID string `json:"id"`
}

// ProvenanceRecipe describes the actions performed by the builder.
type ProvenanceRecipe struct {
	Type string `json:"type"`
	// DefinedInMaterial can be sent as the null pointer to indicate that
	// the value is not present.
	// DefinedInMaterial *int        `json:"definedInMaterial,omitempty"`
	EntryPoint  string      `json:"entryPoint"`
	Arguments   interface{} `json:"arguments,omitempty"`
	Environment interface{} `json:"environment,omitempty"`
}

// ProvenanceMetadata contains metadata for the built artifact.
type ProvenanceMetadata struct {
	// Use pointer to make sure that the abscense of a time is not
	// encoded as the Epoch time.
	BuildStartedOn  *time.Time         `json:"buildStartedOn,omitempty"`
	BuildFinishedOn *time.Time         `json:"buildFinishedOn,omitempty"`
	Completeness    ProvenanceComplete `json:"completeness"`
	Reproducible    bool               `json:"reproducible"`
}

// ProvenanceMaterial defines the materials used to build an artifact.
type ProvenanceMaterial struct {
	URI    string    `json:"uri"`
	Digest DigestSet `json:"digest,omitempty"`
}

// ProvenanceComplete indicates whether the claims in build/recipe are complete.
// For in depth information refer to the specifictaion:
// https://github.com/in-toto/attestation/blob/v0.1.0/spec/predicates/provenance.md
type ProvenanceComplete struct {
	Arguments   bool `json:"arguments"`
	Environment bool `json:"environment"`
	Materials   bool `json:"materials"`
}

// DigestSet contains a set of digests. It is represented as a map from
// algorithm name to lowercase hex-encoded value.
type DigestSet map[string]string

type IntotoStatement struct {
	intoto.StatementHeader
	Pred ProvenancePredicate `json:"predicate"`
}

func New(payload []byte) (iface.Statement, error) {
	var statement IntotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	return &statement, nil
}

func (stmt *IntotoStatement) Predicate() (interface{}, error) {
	return stmt.Pred, nil
}

func (stmt *IntotoStatement) Header() (intoto.StatementHeader, error) {
	return stmt.StatementHeader, nil
}

// BuilderID implements Statement.BuilderID.
func (stmt *IntotoStatement) BuilderID() (string, error) {
	return stmt.Pred.Builder.ID, nil
}

// BuildType implements Statement.BuildType.
func (stmt *IntotoStatement) BuildType() (string, error) {
	return stmt.Pred.Recipe.Type, nil
}

// BuildType implements Statement.GetSystemParameters.
func (stmt *IntotoStatement) GetSystemParameters() (map[string]any, error) {
	arguments := stmt.Pred.Recipe.Arguments
	argsMap, ok := arguments.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: cannot cast arguments as map", common.ErrSubstitution)
	}

	substitutions, ok := argsMap["substitutions"]
	if !ok {
		return nil, fmt.Errorf("%w: no 'substitutions' field", common.ErrSubstitution)
	}

	m, ok := substitutions.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: cannot convert substitutions to a map", common.ErrSubstitution)
	}
	return m, nil
}

// SourceURI implements Statement.SourceURI.
func (stmt *IntotoStatement) SourceURI() (string, error) {
	if len(stmt.Pred.Materials) == 0 {
		return "", fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no material")
	}
	uri := stmt.Pred.Materials[0].URI
	if uri == "" {
		return "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}

	return uri, nil
}

// Subjects implements Statement.Subjects.
func (stmt *IntotoStatement) Subjects() ([]intoto.Subject, error) {
	subj := stmt.StatementHeader.Subject
	if len(subj) == 0 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, "no subjects")
	}
	return subj, nil
}
