package utils

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

// TrustedAttesterID represents an identifier that has been explicitly trusted.
// TODO: don't embed TrustedBuilderID, use a whole new type that implements the
// Name, Version, and String, and maybe also MatchesLoose and MatchesFull. (using semver?)
type TrustedAttesterID struct {
	TrustedBuilderID
}

// TrustedAttesterIDNew creates a new AttesterID structure.
func TrustedAttesterIDNew(attesterID string, needVersion bool) (*TrustedAttesterID, error) {
	builderID, err := TrustedBuilderIDNew(attesterID, needVersion)
	if err != nil {
		return nil, err
	}
	trustedAttesterID := &TrustedAttesterID{
		TrustedBuilderID: *builderID,
	}
	return trustedAttesterID, nil
}

// TrustedBuilderID represents a builder ID that has been explicitly trusted.
type TrustedBuilderID struct {
	name, version string
}

// TrustedBuilderIDNew creates a new BuilderID structure.
func TrustedBuilderIDNew(builderID string, needVersion bool) (*TrustedBuilderID, error) {
	name, version, err := ParseBuilderID(builderID, needVersion)
	if err != nil {
		return nil, err
	}

	return &TrustedBuilderID{
		name:    name,
		version: version,
	}, nil
}

// MatchesLoose matches the builderID string against the reference builderID.
// If the builderID contains a semver, the full builderID must match.
// Otherwise, only the name needs to match.
// `allowRef: true` indicates that the matching need not be an eaxct
// match. In this case, if the BuilderID version is a GitHub ref
// `refs/tags/name`, we will consider it equal to user-provided
// builderID `name`.
func (b *TrustedBuilderID) MatchesLoose(builderID string, allowRef bool) error {
	name, version, err := ParseBuilderID(builderID, false)
	if err != nil {
		return err
	}

	if name != b.name {
		return fmt.Errorf("%w: expected name '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			b.name, name)
	}

	if version != "" && version != b.version {
		// If allowRef is true, try the long version `refs/tags/<name>` match.
		if allowRef &&
			"refs/tags/"+version == b.version {
			return nil
		}
		return fmt.Errorf("%w: expected version '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			version, b.version)
	}

	return nil
}

// MatchesFull matches the builderID string against the reference builderID.
// Both the name and versions are always verified.
func (b *TrustedBuilderID) MatchesFull(builderID string, allowRef bool) error {
	name, version, err := ParseBuilderID(builderID, false)
	if err != nil {
		return err
	}

	if name != b.name {
		return fmt.Errorf("%w: expected name '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			b.name, name)
	}

	if version != b.version {
		// If allowRef is true, try the long version `refs/tags/<name>` match.
		if allowRef &&
			"refs/tags/"+version == b.version {
			return nil
		}
		return fmt.Errorf("%w: expected version '%s', got '%s'", serrors.ErrorMismatchBuilderID,
			version, b.version)
	}

	return nil
}

// Name returns the trusted builder's name.
func (b *TrustedBuilderID) Name() string {
	return b.name
}

// Version returns the trusted builder's version reference if any.
func (b *TrustedBuilderID) Version() string {
	return b.version
}

// String returns the full trusted builder ID as a string.
func (b *TrustedBuilderID) String() string {
	if b.version == "" {
		return b.name
	}
	return fmt.Sprintf("%s@%s", b.name, b.version)
}

// ParseBuilderID parses the builder ID into the URI and ref parts.
func ParseBuilderID(id string, needVersion bool) (string, string, error) {
	parts := strings.Split(id, "@")
	if len(parts) == 2 {
		if parts[1] == "" {
			return "", "", fmt.Errorf("%w: builderID: '%s'",
				serrors.ErrorInvalidFormat, id)
		}
		return parts[0], parts[1], nil
	}

	if len(parts) == 1 && !needVersion {
		return parts[0], "", nil
	}

	return "", "", fmt.Errorf("%w: builderID: '%s'",
		serrors.ErrorInvalidFormat, id)
}

// IsValidBuilderTag validates if the given ref is a valid builder tag.
func IsValidBuilderTag(ref string, testing bool) error {
	// Extract the pin.
	pin, err := TagFromGitRef(ref)
	if err != nil {
		return err
	}

	if testing {
		// Tags on trusted repositories should be a valid semver with version
		// core including all three parts and no build identifier.
		versionCore := strings.Split(pin, "-")[0]
		if !semver.IsValid(pin) ||
			len(strings.Split(versionCore, ".")) != 3 ||
			semver.Build(pin) != "" {
			return fmt.Errorf("%w: %s: version tag not valid", serrors.ErrorInvalidRef, pin)
		}
		return nil
	}

	// Valid semver of the form vX.Y.Z with no metadata.
	if !semver.IsValid(pin) ||
		len(strings.Split(pin, ".")) != 3 ||
		semver.Prerelease(pin) != "" ||
		semver.Build(pin) != "" {
		return fmt.Errorf("%w: %s: not of the form vX.Y.Z", serrors.ErrorInvalidRef, pin)
	}
	return nil
}

func IsValidJreleaserBuilderTag(ref string) error {
	// Extract the pin.
	pin, err := TagFromGitRef(ref)
	if err != nil {
		return err
	}

	// Valid semver of the form vX.Y.Z-<language> with no metadata.
	// NOTE: When adding a language, update the corresponding
	// unit test.
	languages := map[string]bool{
		"-java": true,
	}
	_, validLanguage := languages[semver.Prerelease(pin)]
	if !semver.IsValid(pin) ||
		len(strings.Split(pin, ".")) != 3 ||
		!validLanguage ||
		semver.Build(pin) != "" {
		return fmt.Errorf("%w: %s: not of the form vX.Y.Z-<language>", serrors.ErrorInvalidRef, pin)
	}
	return nil
}
