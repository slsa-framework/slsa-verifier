package utils

import (
	"fmt"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"golang.org/x/mod/semver"
)

func VerifyVersionedTag(provenanceTag, expectedTag string) error {
	if !semver.IsValid(expectedTag) {
		return fmt.Errorf("%s: %w", expectedTag, serrors.ErrorInvalidSemver)
	}

	semTag := semver.Canonical(provenanceTag)
	if !semver.IsValid(semTag) {
		return fmt.Errorf("%s: %w", provenanceTag, serrors.ErrorInvalidSemver)
	}

	// Major should always be the same.
	expectedMajor := semver.Major(expectedTag)
	major := semver.Major(semTag)
	if major != expectedMajor {
		return fmt.Errorf("%w: major version expected '%s', got '%s'",
			serrors.ErrorMismatchVersionedTag, expectedMajor, major)
	}

	expectedMinor, err := minorVersion(expectedTag)
	if err == nil {
		// A minor version was provided by the user.
		minor, err := minorVersion(semTag)
		if err != nil {
			return err
		}

		if minor != expectedMinor {
			return fmt.Errorf("%w: minor version expected '%s', got '%s'",
				serrors.ErrorMismatchVersionedTag, expectedMinor, minor)
		}
	}

	expectedPatch, err := patchVersion(expectedTag)
	if err == nil {
		// A patch version was provided by the user.
		patch, err := patchVersion(semTag)
		if err != nil {
			return err
		}

		if patch != expectedPatch {
			return fmt.Errorf("%w: patch version expected '%s', got '%s'",
				serrors.ErrorMismatchVersionedTag, expectedPatch, patch)
		}
	}

	// Match.
	return nil
}

func minorVersion(v string) (string, error) {
	return extractFromVersion(v, 1)
}

func patchVersion(v string) (string, error) {
	patch, err := extractFromVersion(v, 2)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(patch, semver.Build(v)), nil
}

func extractFromVersion(v string, i int) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) <= i {
		return "", fmt.Errorf("%s: %w", v, serrors.ErrorInvalidSemver)
	}
	return parts[i], nil
}
