package container

import (
	"context"

	crname "github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/oci"
)

var RunCosignImageVerification = func(ctx context.Context,
	image string, co *cosign.CheckOpts) ([]oci.Signature, bool, error) {
	signedImgRef, err := crname.ParseReference(image)
	if err != nil {
		return nil, false, err
	}
	return cosign.VerifyImageAttestations(ctx, signedImgRef, co)
}
