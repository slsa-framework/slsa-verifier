package container

import (
	"context"
	"strings"

	crname "github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/oci"
)

var GetImageDigest = func(imageReference string) (string, error) {
	ref, err := crname.ParseReference(imageReference)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(ref.Context().Digest(ref.Identifier()).DigestStr(), "sha256:"), nil
}

var RunCosignImageVerification = func(ctx context.Context,
	imageReference string, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	signedImgRef, err := crname.ParseReference(imageReference)
	if err != nil {
		return nil, false, err
	}
	return cosign.VerifyImageAttestations(ctx, signedImgRef, co)
}
