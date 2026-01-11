// Copyright 2023 SLSA Authors
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

func computeFileHash(filePath string, h hash.Hash) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// computeArtifactHash returns the hash of the artifact.
// If artifact is a digest (sha256:xxx or sha512:xxx), it parses and validates it.
// Otherwise, it computes the SHA256 hash of the file at the given path.
func computeArtifactHash(artifact string) (string, error) {
	if strings.HasPrefix(artifact, "sha256:") || strings.HasPrefix(artifact, "sha512:") {
		return parseDigest(artifact)
	}
	return computeFileHash(artifact, sha256.New())
}

// parseDigest parses and validates a digest string in the format "algorithm:hexvalue"
// and returns the hex value.
func parseDigest(digest string) (string, error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid digest format: %s", digest)
	}
	algorithm := parts[0]
	h := parts[1]

	expectedLen := map[string]int{"sha256": 64, "sha512": 128}
	exp, ok := expectedLen[algorithm]
	if !ok {
		return "", fmt.Errorf("unsupported digest algorithm: %s (supported: sha256, sha512)", algorithm)
	}
	if len(h) != exp {
		return "", fmt.Errorf("invalid %s digest length: expected %d characters, got %d", algorithm, exp, len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("invalid hex in digest: %s", h)
	}

	return h, nil
}
