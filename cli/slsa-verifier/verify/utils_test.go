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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDigest(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid sha256",
			input:   "sha256:" + strings.Repeat("a", 64),
			want:    strings.Repeat("a", 64),
			wantErr: false,
		},
		{
			name:    "valid sha512",
			input:   "sha512:" + strings.Repeat("b", 128),
			want:    strings.Repeat("b", 128),
			wantErr: false,
		},
		{
			name:    "valid sha256 with mixed case hex",
			input:   "sha256:" + strings.Repeat("aB", 32),
			want:    strings.Repeat("aB", 32),
			wantErr: false,
		},
		{
			name:    "sha256 wrong length - too short",
			input:   "sha256:abc",
			want:    "",
			wantErr: true,
		},
		{
			name:    "sha256 wrong length - too long",
			input:   "sha256:" + strings.Repeat("a", 65),
			want:    "",
			wantErr: true,
		},
		{
			name:    "sha512 wrong length",
			input:   "sha512:" + strings.Repeat("a", 64),
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid hex characters",
			input:   "sha256:" + strings.Repeat("g", 64),
			want:    "",
			wantErr: true,
		},
		{
			name:    "unsupported algorithm sha384",
			input:   "sha384:" + strings.Repeat("a", 96),
			want:    "",
			wantErr: true,
		},
		{
			name:    "unsupported algorithm md5",
			input:   "md5:" + strings.Repeat("a", 32),
			want:    "",
			wantErr: true,
		},
		{
			name:    "missing colon",
			input:   "sha256" + strings.Repeat("a", 64),
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty hash value",
			input:   "sha256:",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDigest(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeArtifactHash(t *testing.T) {
	// Create a temporary file for testing file hash computation
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(tmpFile, content, 0o600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	// SHA256 of "hello world" is b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "sha256 digest",
			input:   "sha256:" + strings.Repeat("a", 64),
			want:    strings.Repeat("a", 64),
			wantErr: false,
		},
		{
			name:    "sha512 digest",
			input:   "sha512:" + strings.Repeat("b", 128),
			want:    strings.Repeat("b", 128),
			wantErr: false,
		},
		{
			name:    "file path",
			input:   tmpFile,
			want:    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			wantErr: false,
		},
		{
			name:    "invalid digest format",
			input:   "sha256:invalid",
			want:    "",
			wantErr: true,
		},
		{
			name:    "non-existent file",
			input:   "/non/existent/file.txt",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := computeArtifactHash(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("computeArtifactHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("computeArtifactHash() = %v, want %v", got, tt.want)
			}
		})
	}
}
