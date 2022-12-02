package container

import (
	"fmt"
	"os"
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

// ValidateArtifactReference verifies that the reference is immutable
// and has digest `digest`.
func ValidateArtifactReference(image, expectedDigest string) error {
	// Check if the image refers to a file.
	// If it does, we don't expect users to provide an 'imutable'
	// reference with `@sha256:xxx`.
	_, err := os.Stat(image)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("os.Stat(): %w", err)
	}
	if !os.IsNotExist(err) {
		return nil
	}

	// For image in a registry, only allow immutable images.
	ref, err := crname.ParseReference(image)
	if err != nil {
		return fmt.Errorf("crane.ParseReference(): %w", err)
	}

	if !strings.HasPrefix(ref.Identifier(), "sha256:") {
		return fmt.Errorf("%w: expected '%s@sha256:%s', got '%s'",
			serrors.ErrorMutableImage, image, expectedDigest, image)
	}

	digest := strings.TrimPrefix(ref.Identifier(), "sha256:")
	if expectedDigest != digest {
		return fmt.Errorf("%w: expected digest '%s', got '%s'",
			serrors.ErrorInternal, expectedDigest, digest)
	}

	return nil
}
