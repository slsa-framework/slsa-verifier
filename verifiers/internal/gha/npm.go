package gha

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/internal/gha/slsaprovenance"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

const (
	publishAttestationV01 = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
)

var errrorInvalidAttestations = errors.New("invalid npm attestations")

type attestation struct {
	PredicateType string      `json:"predicateType"`
	BundleBytes   BundleBytes `json:"bundle"`
}

type BundleBytes []byte

func (b *BundleBytes) UnmarshalJSON(data []byte) error {
	*b = data
	return nil
}

// type BundleWrap struct {
// 	bundle_v1.Bundle
// }

// NOTE: do not unmarshal the bundle field.
// func (b *BundleWrap) UnmarshalJSON(data []byte) error {
// 	if err := protojson.Unmarshal(data, b); err != nil {
// 		return fmt.Errorf("%w: %s", serrors.ErrorInvalidEncoding, err)
// 	}
// 	return nil
// }

type Npm struct {
	ctx                   context.Context
	root                  *TrustedRoot
	verifiedProvenanceAtt *SignedAttestation
	verifiedPublishAtt    *SignedAttestation
	provenanceAttestation *attestation
	publishAttestation    *attestation
}

func NpmNew(ctx context.Context, root *TrustedRoot, attestationBytes []byte) (*Npm, error) {
	var attestations []attestation
	if err := json.Unmarshal(attestationBytes, &attestations); err != nil {
		return nil, fmt.Errorf("%w: json.Unmarshal: %v", errrorInvalidAttestations, err)
	}

	if len(attestations) != 2 {
		return nil, fmt.Errorf("%w: invalid number of attestations: %v", errrorInvalidAttestations, len(attestations))
	}

	// Verify the provenance predicate.
	if err := verifyPredicate(attestations[0], slsaprovenance.ProvenanceV02Type); err != nil {
		return nil, err
	}

	// Verify the publish predicate.
	if err := verifyPredicate(attestations[1], publishAttestationV01); err != nil {
		return nil, err
	}

	return &Npm{
		ctx:                   ctx,
		root:                  root,
		provenanceAttestation: &attestations[0],
		publishAttestation:    &attestations[1],
	}, nil
}

func (n *Npm) verifyProvenanceAttestationSignature() error {
	// We jut re-use the standard bundle verification.
	signedProvenance, err := VerifyProvenanceBundle(n.ctx, n.provenanceAttestation.BundleBytes, n.root)
	if err != nil {
		return err
	}
	n.verifiedProvenanceAtt = signedProvenance
	return nil
}

func (n *Npm) verifyPublishAttesttationSignature() error {
	// First verify the bundle and its rekor entry.
	signedPublish, err := verifyBundleAndEntryFromBytes(n.ctx, n.publishAttestation.BundleBytes, n.root, false)
	if err != nil {
		return err
	}

	// Second, we verify the signature, which ues a static key.
	// Extract payload.
	env := signedPublish.Envelope
	payload, err := utils.PayloadFromEnvelope(env)
	if err != nil {
		return err
	}

	// Extract the signature.
	if len(env.Signatures) == 0 {
		return fmt.Errorf("%w: no signatures found in envelope", serrors.ErrorNoValidSignature)
	}

	// The registry signs with a single, static, non-rotated key.
	sig := env.Signatures[0].Sig
	// TODO: verify the keyid, both in DSSE and hint.

	// Verify the signature.
	/*
		NOTE: key available at https://registry.npmjs.org/-/npm/v1/keys
			  https://docs.npmjs.com/about-registry-signatures
			{
		  "keys": [
		    {
		      "expires": null,
		      "keyid": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
		      "keytype": "ecdsa-sha2-nistp256",
		      "scheme": "ecdsa-sha2-nistp256",
		      "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="
		    }
		  ]
		}
	*/
	payloadHash := sha256.Sum256(payload)
	b64key := "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg=="
	rawKey, err := base64.StdEncoding.DecodeString(b64key)
	if err != nil {
		return fmt.Errorf("DecodeString: %w", err)
	}

	key, err := x509.ParsePKIXPublicKey(rawKey)
	if err != nil {
		return fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: public key not of type ECDSA", err)
	}

	// TODO: check the keyid
	rsig, err := utils.DecodeSignature(sig)
	if err != nil {
		return fmt.Errorf("decodeSigature: %w: %s", serrors.ErrorInvalidEncoding, err)
	}

	if ecdsa.VerifyASN1(pubKey, payloadHash[:], rsig) {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, sig)
	}

	// Verification done.
	n.verifiedPublishAtt = signedPublish
	return nil
}

func (n *Npm) verifyPackageName(name *string) error {
	if name == nil {
		return nil
	}

	// Verify name in provenance.
	if err := verifyName(n.verifiedProvenanceAtt, *name); err != nil {
		return err
	}

	// Verify name in publish attestation.
	if err := verifyName(n.verifiedPublishAtt, *name); err != nil {
		return err
	}

	return nil
}

func verifyName(att *SignedAttestation, name string) error {
	prov, err := slsaprovenance.ProvenanceFromEnvelope(att.Envelope)
	if err != nil {
		return nil
	}

	subjects, err := prov.Subjects()
	if err != nil {
		return fmt.Errorf("%w")
	}
	if len(subjects) != 1 {
		return fmt.Errorf("TODO")
	}

	// Package name starts with a prefix.
	prefix := "pkg:npm/"
	if !strings.HasPrefix(string(subjects[0].Name), prefix) {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidPackageName, subjects[0].Name)
	}

	// URL decode the package name fr the attestation.
	subject, err := url.QueryUnescape(subjects[0].Name[len(prefix):])
	if err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidEncoding, err)
	}

	subName, subTag, err := getNameAndTag(string(subject))
	if err != nil {
		return err
	}
	expName, expTag, err := getNameAndTag(name)
	if err != nil {
		return err
	}

	if subName != expName {
		return fmt.Errorf("TODO:different names")
	}

	if expTag != "" && expTag != subTag {
		return fmt.Errorf("TODO:different tags")
	}

	return nil
}

func getNameAndTag(name string) (string, string, error) {
	n := name
	if strings.HasPrefix(name, "@") {
		n = n[1:]
	}
	parts := strings.Split(n, "@")
	if len(parts) > 2 {
		return "", "", fmt.Errorf("%w: %v", serrors.ErrorInvalidPackageName, name)
	}

	pkgname := parts[0]
	if strings.HasPrefix(name, "@") {
		pkgname = "@" + pkgname
	}

	var pkgtag string
	if len(parts) == 2 {
		pkgtag = parts[1]
	}

	return pkgname, pkgtag, nil
}

// verifyEnvAndCert

func verifyPredicate(att attestation, perdicateType string) error {
	if att.PredicateType != perdicateType {
		return fmt.Errorf("%w: invalid predicate type: %v. Expected %v", errrorInvalidAttestations,
			att.PredicateType, perdicateType)
	}
	return nil
}
