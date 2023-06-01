package utils

import (
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

// ParseGitRef validates that the given git ref is a valid ref of the given type and returns its name.
func ParseGitRef(refType, ref string) (string, error) {
	refPrefix := fmt.Sprintf("refs/%s/", refType)
	if !strings.HasPrefix(ref, refPrefix) {
		return "", fmt.Errorf("%w: %s: not of the form '%s<name>'", serrors.ErrorInvalidRef, ref, refPrefix)
	}

	name := strings.TrimPrefix(ref, refPrefix)
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("%w: %s: not of the form '%s<name>'", serrors.ErrorInvalidRef, ref, refPrefix)
	}

	return name, nil
}

// TagFromGitRef returns the tagname from a tag ref.
func TagFromGitRef(ref string) (string, error) {
	return ParseGitRef("tags", ref)
}

// BranchFromGitRef returns the tagname from a tag ref.
func BranchFromGitRef(ref string) (string, error) {
	return ParseGitRef("heads", ref)
}
