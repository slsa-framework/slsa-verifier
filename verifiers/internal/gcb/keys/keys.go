package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"path"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

//go:embed materials/*
var publicKeys embed.FS

const (
	// v1.0 global keys.
	// Run command `gcloud kms keys versions get-public-key 1 --keyring attestor --key google-hosted-worker --project verified-builder --location global`.
	V10_GlobalPAEKeyID = "projects/verified-builder/locations/global/keyRings/attestor/cryptoKeys/google-hosted-worker/cryptoKeyVersions/1"

	// v0.1 global keys.
	// Run command `gcloud kms keys versions get-public-key 1 --keyring attestor --key provenanceSigner --project verified-builder --location global`.
	V01_GlobalPAEKeyID = "projects/verified-builder/locations/global/keyRings/attestor/cryptoKeys/provenanceSigner/cryptoKeyVersions/1"
)

var globalKeyNames = map[string]string{
	V10_GlobalPAEKeyID: "global-pae-google-hosted-worker_1",
	V01_GlobalPAEKeyID: "global-pae-provenanceSigner_1",
}

type PublicKey struct {
	value  []byte
	pubKey *ecdsa.PublicKey
	region string
	// TODO: key type and size
}

func NewPublicKey(region string) (*PublicKey, error) {
	content, err := fs.ReadFile(publicKeys, path.Join("materials", region+".key"))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read key materials", err)
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidPEM, content)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: public key not of type ECDSA", err)
	}

	return &PublicKey{
		value:  content,
		pubKey: pubKey,
		region: region,
	}, nil
}

func (p *PublicKey) VerifySignature(digest [32]byte, sig []byte) error {
	if p.pubKey == nil {
		return fmt.Errorf("%w: key is empty", serrors.ErrorInternal)
	}
	if !ecdsa.VerifyASN1(p.pubKey, digest[:], sig) {
		return fmt.Errorf("%w: cannot verify with public key '%v'",
			serrors.ErrorInvalidSignature, p.region)
	}

	return nil
}

func (p *PublicKey) Name() string {
	return p.region
}

type GlobalPAEKey struct {
	publicKey *PublicKey
	id        string
	Verifier  *dsselib.EnvelopeVerifier
}

func NewGlobalPAEKey(id string) (*GlobalPAEKey, error) {
	name, ok := globalKeyNames[id]
	if !ok {
		return nil, fmt.Errorf("%w: unknown key %v", serrors.ErrorInternal, id)
	}

	publicKey, err := NewPublicKey(name)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to create public key for Global PAE key %v", err, name)
	}

	globalPaeKey := &GlobalPAEKey{
		publicKey: publicKey,
		id:        id,
	}
	envVerifier, err := dsselib.NewEnvelopeVerifier(globalPaeKey)
	if err != nil {
		return nil, err
	}
	globalPaeKey.Verifier = envVerifier
	return globalPaeKey, nil
}

func (v *GlobalPAEKey) VerifyPAESignature(envelope *dsselib.Envelope) error {
	_, err := v.Verifier.Verify(context.Background(), envelope)
	return err
}

// Verify implements dsse.Verifier.Verify. It verifies
// a signature formatted in DSSE-conformant PAE.
func (v *GlobalPAEKey) Verify(_ context.Context, data, sig []byte) error {
	// Verify the signature.
	digest := sha256.Sum256(data)
	return v.publicKey.VerifySignature(digest, sig)
}

// KeyID implements dsse.Verifier.KeyID.
func (v *GlobalPAEKey) KeyID() (string, error) {
	return v.id, nil
}

// Public implements dsse.Verifier.Public.
func (v *GlobalPAEKey) Public() crypto.PublicKey {
	return v.publicKey
}

func (v *GlobalPAEKey) Name() string {
	return v.publicKey.Name()
}
