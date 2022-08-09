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
	Value  []byte
	Region string
	// TODO: key type and size
}

func PublicKeyNew(region string) (*PublicKey, error) {
	content, err := fs.ReadFile(publicKeys, path.Join("materials", region+".key"))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read key materials", err)
	}

	return &PublicKey{
		Value:  content,
		Region: region,
	}, nil
}

func (self *PublicKey) VerifySignature(digest [32]byte, sig []byte) error {
	block, _ := pem.Decode(self.Value)
	if block == nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidPEM, self.Value)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: public key not of type ECDSA", err)
	}

	if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
		return fmt.Errorf("%w: cannot verify with public key '%v'",
			serrors.ErrorInvalidSignature, string(self.Region))
	}

	return nil
}

// TODO: load public keys
/*func init() {

	pubKey, err := PublicKeyNew("asia-east1")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(pubKey.Value))
}
*/
