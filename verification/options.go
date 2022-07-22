package verification

// ProvenanceOpts are the options for checking provenance information.
type ProvenanceOpts struct {
	// ExpectedDigest is the expected artifact sha included in the provenance
	ExpectedDigest string

	// ExpectedBranch is the expected branch (github_ref or github_base_ref) in
	// the invocation parameters.
	ExpectedBranch string

	// ExpectedTag is the expected tag, github_ref, in the invocation parameters.
	ExpectedTag *string

	// ExpectedVersionedTag is the expected versioned tag
	ExpectedVersionedTag *string
}
