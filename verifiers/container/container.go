package container

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
)

var GetImageDigest = func(image string) (string, error) {
	digest, err := crane.Digest(image)
	if err != nil {
		return "", fmt.Errorf("crane.Digest(): %w", err)
	}
	return strings.TrimPrefix(digest, "sha256:"), nil
}
