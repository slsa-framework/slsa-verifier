// Copyright 2022 SLSA Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verify

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers"
)

// VerifyVSACommand contains the parameters for the verify-vsa command.
type VerifyVSACommand struct {
	SubjectDigests   *[]string
	AttestationPath  *string
	VerifierID       *string
	ResourceURI      *string
	VerifiedLevels   *[]string
	PrintAttestation bool
	PublicKeyPath    *string
	PublicKeyID      *string
}

// Exec executes the verifiers.VerifyVSA.
func (c *VerifyVSACommand) Exec(ctx context.Context) error {
	vsaOpts := &options.VSAOpts{
		ExpectedDigests:        c.SubjectDigests,
		ExpectedVerifierID:     c.VerifierID,
		ExpectedResourceURI:    c.ResourceURI,
		ExpectedVerifiedLevels: c.VerifiedLevels,
	}
	pubKeyBytes, err := os.ReadFile(*c.PublicKeyPath)
	if err != nil {
		printFailed(err)
		return err
	}
	pubKey, err := cryptoutils.UnmarshalPEMToPublicKey(pubKeyBytes)
	if err != nil {
		err = fmt.Errorf("%w: %w", serrors.ErrorInvalidPublicKey, err)
		printFailed(err)
		return err
	}
	hashAlgo := determineSignatureHashAlgo(pubKey)
	VerificationOpts := &options.VerificationOpts{
		PublicKey:         pubKey,
		PublicKeyID:       c.PublicKeyID,
		PublicKeyHashAlgo: hashAlgo,
	}
	attestation, err := os.ReadFile(*c.AttestationPath)
	if err != nil {
		printFailed(err)
		return err
	}
	vsaBytes, err := verifiers.VerifyVSA(ctx, attestation, vsaOpts, VerificationOpts)
	if err != nil {
		printFailed(err)
		return err
	}
	if c.PrintAttestation {
		fmt.Fprintf(os.Stdout, "%s\n", string(vsaBytes))
	}
	fmt.Fprintf(os.Stderr, "Verifying VSA: PASSED\n\n")
	// verfiers.VerifyVSA already checks if the producerID matches
	return nil
}

// printFailed prints the error message to stderr.
func printFailed(err error) {
	fmt.Fprintf(os.Stderr, "Verifying VSA: FAILED: %v\n\n", err)
}

// determineSignatureHashAlgo determines the hash algorithm used to compute the digest to be signed, based on the public key.
// some well-known defaults can be determined, otherwise the it returns crypto.SHA256.
func determineSignatureHashAlgo(pubKey crypto.PublicKey) crypto.Hash {
	var h crypto.Hash
	switch pk := pubKey.(type) {
	case *rsa.PublicKey:
		h = crypto.SHA256
	case *ecdsa.PublicKey:
		switch pk.Curve {
		case elliptic.P256():
			h = crypto.SHA256
		case elliptic.P384():
			h = crypto.SHA384
		case elliptic.P521():
			h = crypto.SHA512
		default:
			h = crypto.SHA256
		}
	case ed25519.PublicKey:
		h = crypto.SHA512
	default:
		h = crypto.SHA256
	}
	return h
}
