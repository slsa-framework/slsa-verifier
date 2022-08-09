package container

import (
	crname "github.com/google/go-containerregistry/pkg/name"
)

func GetImageDigest(imageReference string) (string, error) {
	ref, err := crname.ParseReference(imageReference)
	if err != nil {
		return "", err
	}
	return ref.Context().Digest(ref.Identifier()).DigestStr(), nil
}
