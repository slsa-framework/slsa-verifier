package iface

import (
	intoto "github.com/in-toto/in-toto-golang/in_toto"
)

// Statement represents statement for a predicate type and build type.
type Statement interface {
	// header returns the statement header.
	Header() (intoto.StatementHeader, error)

	// BuilderID returns the builder id in the predicate.
	BuilderID() (string, error)

	// BuildType returns the buildType.
	BuildType() (string, error)

	// SourceURI is the full URI (including tag).
	SourceURI() (string, error)

	// Subject is the list of intoto subjects in the provenance.
	Subjects() ([]intoto.Subject, error)

	// Get system pararmeters.
	GetSystemParameters() (map[string]any, error)
}
