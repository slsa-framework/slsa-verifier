package gha

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

var (
	testTargetKeysFileContent = `{
		"keys": [
			{
				"keyId": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
				"keyUsage": "npm:signatures",
				"publicKey": {
					"rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==",
					"keyDetails": "PKIX_ECDSA_P256_SHA_256",
					"validFor": {
						"start": "1999-01-01T00:00:00.000Z"
					}
				}
			},
			{
				"keyId": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
				"keyUsage": "npm:attestations",
				"publicKey": {
					"rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==",
					"keyDetails": "PKIX_ECDSA_P256_SHA_256",
					"validFor": {
						"start": "2022-12-01T00:00:00.000Z"
					}
				}
			}
		]
	}`
	testTargetInvalidJSONFileContent = `{
		blah
		"keys": [
			{
				"keyId": "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"
			}
		]
	}`
	normalTargetPath          = "registry.npmjs.org/keys.json"
	testTargetPath            = "my-registry.npmjs.org/keys.json"
	testTargetInvalidJSONPath = "my-registry.npmjs.org/keys-invalid-json.json"
	mockFileContentMap        = map[string]string{
		normalTargetPath:          testTargetKeysFileContent,
		testTargetPath:            testTargetKeysFileContent,
		testTargetInvalidJSONPath: testTargetInvalidJSONFileContent,
	}
	testTargetKeys = npmjsKeysTarget{
		Keys: []key{
			{
				KeyID:    "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
				KeyUsage: "npm:signatures",
				PublicKey: publicKey{
					RawBytes:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==",
					KeyDetails: "PKIX_ECDSA_P256_SHA_256",
					ValidFor: validFor{
						Start: time.Date(1999, time.January, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
			{
				KeyID:    "SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
				KeyUsage: "npm:attestations",
				PublicKey: publicKey{
					RawBytes:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==",
					KeyDetails: "PKIX_ECDSA_P256_SHA_256",
					ValidFor: validFor{
						Start: time.Date(2022, time.December, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
		},
	}
	testTargetKey      = testTargetKeys.Keys[1]
	testTargetKeyID    = testTargetKey.KeyID
	testTargetKeyUsage = testTargetKey.KeyUsage
	testTargetKeyData  = testTargetKey.PublicKey.RawBytes
)

// mockSigstoreTUFClient a mock implementation of sigstoreTUFClient.
type mockSigstoreTUFClient struct {
	fileContentMap map[string]string
}

// newMockSigstoreTUFClient returns an instance of the mock client,
// with fileContentMap as input and outputs of the GetTarget() method.
func newMockSigstoreTUFClient() *mockSigstoreTUFClient {
	return &mockSigstoreTUFClient{fileContentMap: mockFileContentMap}
}

// GetTarget mock implementation of GetTarget for the mockSigstoreTUFClient.
func (c mockSigstoreTUFClient) GetTarget(targetPath string) ([]byte, error) {
	content, exists := c.fileContentMap[targetPath]
	if !exists {
		return nil, fmt.Errorf("content not definied in this mock, key: %s", targetPath)
	}
	return []byte(content), nil
}

// TestGetNpmjsKeysTarget ensures we can parse the target file.
func TestGetNpmjsKeysTarget(t *testing.T) {
	tests := []struct {
		name         string
		targetPath   string
		expectedKeys *npmjsKeysTarget
		expectedErr  error
	}{
		{
			name:         "parsing local registry.npmjs.org_keys.json",
			targetPath:   testTargetPath,
			expectedKeys: &testTargetKeys,
		},
		{
			name:        "parsing non-existent registry.npmjs.org_keys.json",
			targetPath:  "my-fake-path.json",
			expectedErr: serrors.ErrorCouldNotFindTarget,
		},
		{
			name:        "parsing invalid json",
			targetPath:  testTargetInvalidJSONPath,
			expectedErr: errorCouldNotParseKeys,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSigstoreTUFClient()
			actualKeys, err := getNpmjsKeysTarget(mockClient, tt.targetPath)
			if keyDataDiff := cmp.Diff(tt.expectedKeys, actualKeys, cmpopts.EquateComparable()); keyDataDiff != "" {
				t.Errorf("expected equal values (-want +got):\n%s", keyDataDiff)
			}
			if errorDiff := cmp.Diff(tt.expectedErr, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
		})
	}
}

// TestGetKeyDataWithNpmjsKeysTarget ensure that we find the key material, given keyid and keyusage.
func TestGetKeyDataWithNpmjsKeysTarget(t *testing.T) {
	tests := []struct {
		name            string
		targetPath      string
		keyID           string
		keyUsage        string
		expectedKeyData string
		expectedErr     error
	}{
		{
			name:            "npmjs' first attestation key",
			targetPath:      testTargetPath,
			keyID:           testTargetKeyID,
			keyUsage:        testTargetKeyUsage,
			expectedKeyData: testTargetKeyData,
		},
		{
			name:            "missing another keyUsage",
			targetPath:      testTargetPath,
			keyID:           testTargetKeyID,
			keyUsage:        "npm:somethingelse",
			expectedKeyData: "", // should not be returned in this error case
			expectedErr:     errorMissingNpmjsKeyIDKeyUsage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := newMockSigstoreTUFClient()
			keys, err := getNpmjsKeysTarget(mockClient, tt.targetPath)
			if err != nil {
				t.Fatalf("getNpmjsKeysTarget: %v", err)
			}
			actualKeyData, err := getKeyDataWithNpmjsKeysTarget(keys, tt.keyID, tt.keyUsage)
			if keyDataDiff := cmp.Diff(tt.expectedKeyData, actualKeyData); keyDataDiff != "" {
				t.Errorf("expected equal values (-want +got):\n%s", keyDataDiff)
			}
			if errorDiff := cmp.Diff(tt.expectedErr, err, cmpopts.EquateErrors()); errorDiff != "" {
				t.Errorf("unexpected error (-want +got):\n%s", errorDiff)
			}
		})
	}
}
