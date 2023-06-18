package utils

import (
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

// NormalizeGitURI normalizes a git URI to include a git+https:// prefix.
func NormalizeGitURI(s string) string {
	if !strings.HasPrefix(s, "git+") {
		if !strings.Contains(s, "://") {
			return "git+https://" + s
		}
		return "git+" + s
	}
	return s
}

// ParseGitURIAndRef retrieves the URI and ref from the given URI.
func ParseGitURIAndRef(uri string) (string, string, error) {
	if uri == "" {
		return "", "", fmt.Errorf("%w: empty uri", serrors.ErrorMalformedURI)
	}
	if !strings.HasPrefix(uri, "git+") {
		return "", "", fmt.Errorf("%w: not a git URI: %q", serrors.ErrorMalformedURI, uri)
	}

	r := strings.SplitN(uri, "@", 2)
	if len(r) < 2 {
		return r[0], "", nil
	}

	return r[0], r[1], nil
}

// ParseGitRef parses the git ref and returns its type and name.
func ParseGitRef(ref string) (string, string) {
	parts := strings.SplitN(ref, "/", 3)
	if len(parts) < 3 || parts[0] != "refs" {
		return "", ref
	}
	return parts[1], parts[2]
}

// ValidateGitRef validates that the given git ref is a valid ref of the given type and returns its name.
func ValidateGitRef(refType, ref string) (string, error) {
	typ, name := ParseGitRef(ref)
	if typ != refType {
		return "", fmt.Errorf("%w: %q: unexpected ref type: %q", serrors.ErrorInvalidRef, ref, typ)
	}
	if name == "" {
		return "", fmt.Errorf("%w: %q: empty ref name", serrors.ErrorInvalidRef, ref)
	}

	return name, nil
}

// TagFromGitRef returns the tagname from a tag ref.
func TagFromGitRef(ref string) (string, error) {
	return ValidateGitRef("tags", ref)
}

// BranchFromGitRef returns the tagname from a tag ref.
func BranchFromGitRef(ref string) (string, error) {
	return ValidateGitRef("heads", ref)
}
