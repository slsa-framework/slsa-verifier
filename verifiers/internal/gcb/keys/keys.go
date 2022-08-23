package keys

import (
	"crypto/ecdsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"path"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
)

//go:embed materials/*
var publicKeys embed.FS

type PublicKey struct {
	value  []byte
	pubKey *ecdsa.PublicKey
	region string
	// TODO: key type and size
}

func PublicKeyNew(region string) (*PublicKey, error) {
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

func (self *PublicKey) VerifySignature(digest [32]byte, sig []byte) error {
	if self.pubKey == nil {
		return fmt.Errorf("%w: key is empty", serrors.ErrorInternal)
	}
	if !ecdsa.VerifyASN1(self.pubKey, digest[:], sig) {
		return fmt.Errorf("%w: cannot verify with public key '%v'",
			serrors.ErrorInvalidSignature, string(self.region))
	}

	return nil
}
