package iface

import (
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

// Provenance represents provenance for a predicate type and build type.
type Provenance interface {
	// Predicate returns the predicate.
	Predicate() (any, error)

	// PredicateType returns the predicate type.
	PredicateType() (string, error)

	// Header returns the statement header.
	Header() (intoto.StatementHeader, error)

	// BuilderID returns the builder id in the predicate.
	BuilderID() (string, error)

	// BuildType returns the buildType.
	BuildType() (string, error)

	// SourceURI is the full URI (including tag).
	SourceURI() (string, error)

	// SourceTag is the tag of the source.
	SourceTag() (string, error)

	// SourceBranch is the branch of the source.
	SourceBranch() (string, error)

	// Subject is the list of intoto subjects in the provenance.
	Subjects() ([]intoto.Subject, error)

	// Get system pararmeters.
	GetSystemParameters() (map[string]any, error)
}
