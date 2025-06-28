package gha

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

const (
	attestationKeyUsage = "npm:attestations"
	targetPath          = "registry.npmjs.org/keys.json"
)

var (
	errorMissingNpmjsKeyIDKeyUsage = errors.New("could not find a key with the specified 'keyId' and 'keyUsage'")
	errorCouldNotParseKeys         = errors.New("could not parse keys file content")
)

// npmjsKeysTarget describes the structure of the target file.
type npmjsKeysTarget struct {
	Keys []key `json:"keys"`
}
type key struct {
	KeyID     string    `json:"keyId"`
	KeyUsage  string    `json:"keyUsage"`
	PublicKey publicKey `json:"publicKey"`
}
type publicKey struct {
	RawBytes   string   `json:"rawBytes"`
	KeyDetails string   `json:"keyDetails"`
	ValidFor   validFor `json:"validFor"`
}
type validFor struct {
	Start time.Time `json:"start"`
}

// getNpmjsKeysTarget will fetch and parse the keys.json file in Sigstore's root for npmjs
// The inner TUF client will verify this "blob" is signed with correct delegate TUF roles
// https://github.com/sigstore/root-signing/blob/5fd11f7ec0a993b0f20c335b33e53cfffb986b2e/repository/repository/targets/registry.npmjs.org/7a8ec9678ad824cdccaa7a6dc0961caf8f8df61bc7274189122c123446248426.keys.json#L4
func getNpmjsKeysTarget(client utils.SigstoreTUFClient, targetPath string) (*npmjsKeysTarget, error) {
	blob, err := client.GetTarget(targetPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", serrors.ErrorCouldNotFindTarget, err)
	}
	var keys npmjsKeysTarget
	if err := json.Unmarshal(blob, &keys); err != nil {
		return nil, fmt.Errorf("%w: %w", errorCouldNotParseKeys, err)
	}
	return &keys, nil
}

// getKeyDataWithNpmjsKeysTarget returns the target key's material, given our set of keys, return the target key's material.
// TODO: We may also want to check the existing ValidFor.Start (and a potential future ValidFor.End).
// https://github.com/slsa-framework/slsa-verifier/issues/757
func getKeyDataWithNpmjsKeysTarget(keys *npmjsKeysTarget, keyID, keyUsage string) (string, error) {
	for _, key := range keys.Keys {
		if key.KeyID == keyID && key.KeyUsage == keyUsage {
			return key.PublicKey.RawBytes, nil
		}
	}
	return "", fmt.Errorf("%w: 'keyId': %q, 'keyUsage':%q", errorMissingNpmjsKeyIDKeyUsage, keyID, keyUsage)
}

// getKeyDataFromSigstoreTUF retrieves the keyfile from sigstore's TUF root, parses the file and returns the target key's material.
// See documentation for getNpmjsKeysTarget
//
// example params:
//
//	 client: sigstoreTUFClient
//		keyID: "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
//		keyUsage: "npm:attestations"
func getKeyDataFromSigstoreTUF(client utils.SigstoreTUFClient, keyID, keyUsage string) (string, error) {
	keys, err := getNpmjsKeysTarget(client, targetPath)
	if err != nil {
		return "", err
	}
	KeyData, err := getKeyDataWithNpmjsKeysTarget(keys, keyID, keyUsage)
	if err != nil {
		return "", err
	}
	return KeyData, nil
}
