package keys

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
)

//go:embed materials/*
var publicKeys embed.FS

type PublicKey struct {
	Value []byte
	// TODO: key type and size
}

func PublicKeyNew(region string) (*PublicKey, error) {
	content, err := fs.ReadFile(publicKeys, path.Join("materials", region+".key"))
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read key materials", err)
	}

	return &PublicKey{
		Value: content,
	}, nil
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
