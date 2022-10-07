package gcb

// Copy of github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.1
// This holds an internal copy of in-toto-golang's structs for
// SLSA predicates to handle GCB's incompatibility with the
// published specification. Specifically, GCB provenance currently
// produces a string for ProvenancePredicate.Recipe.DefinedInMaterial
// rather than the compliant signed integer.

import "time"

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

// ProvenanceComplete indicates wheter the claims in build/recipe are complete.
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
