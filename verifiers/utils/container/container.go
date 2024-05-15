package container

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	crname "github.com/google/go-containerregistry/pkg/name"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func GetImageDigest(image string) (string, error) {
	digest, err := crane.Digest(image)
	if err != nil {
		return "", fmt.Errorf("%w: crane.Digest(): %v", serrors.ErrorImageHash, err)
	}
	return strings.TrimPrefix(digest, "sha256:"), nil
}

// GetDigestFromImmutableReference verifies that the reference is immutable
// and returns the `digest`.
func GetDigestFromImmutableReference(image string) (string, error) {
	// Only allow immutable images.
	ref, err := crname.ParseReference(image)
	if err != nil {
		return "", fmt.Errorf("crane.ParseReference(): %w", err)
	}

	if !strings.HasPrefix(ref.Identifier(), "sha256:") {
		return "", fmt.Errorf("%w: '%s'",
			serrors.ErrorMutableImage, image)
	}

	return strings.TrimPrefix(ref.Identifier(), "sha256:"), nil
}
