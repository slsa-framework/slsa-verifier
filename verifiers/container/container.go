package container

import (
	"strings"

	crname "github.com/google/go-containerregistry/pkg/name"
)

var GetImageDigest = func(image string) (string, error) {
	ref, err := crname.ParseReference(image)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(ref.Context().Digest(ref.Identifier()).DigestStr(), "sha256:"), nil
}
