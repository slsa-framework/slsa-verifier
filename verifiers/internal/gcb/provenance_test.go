package gcb

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	//"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
	"github.com/slsa-framework/slsa-verifier/options"
)

// This function sets the statement of the proveannce, as if
// it had been verified. This is necessary because individual functions
// expect this statement to be populated; and this is done only
// after the signatue is verified.
func setStatement(gcb *Provenance) error {
	var statement v01IntotoStatement
	payload, err := payloadFromEnvelope(&gcb.gcloudProv.ProvenanceSummary.Provenance[0].Envelope)
	if err != nil {
		return fmt.Errorf("payloadFromEnvelope: %w", err)
	}
	if err := json.Unmarshal(payload, &statement); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err.Error())
	}
	gcb.verifiedIntotoStatement = &statement
	gcb.verifiedProvenance = &gcb.gcloudProv.ProvenanceSummary.Provenance[0]
	return nil
}

func Test_VerifyIntotoHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
		},
		{
			name:     "invalid intoto header",
			path:     "./testdata/gcloud-container-invalid-intotoheader.json",
			expected: serrors.ErrorInvalidDssePayload,
		},
		{
			name:     "invalid provenance header",
			path:     "./testdata/gcloud-container-invalid-slsaheader.json",
			expected: serrors.ErrorInvalidDssePayload,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			err = prov.VerifyIntotoHeaders()
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyBuilder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		path      string
		builderID string
		expected  error
	}{
		{
			name:      "valid gcb provenance",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
		},
		{
			name:      "mismatch builder.id version",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.1",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "mismatch builder.id name",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "https://cloudbuild.googleapis.com/GoogleHostedWorke@v0.2",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:      "mismatch builder.id protocol",
			path:      "./testdata/gcloud-container-github.json",
			builderID: "http://cloudbuild.googleapis.com/GoogleHostedWorker@v0.2",
			expected:  serrors.ErrorMismatchBuilderID,
		},
		{
			name:     "mismatch recipe.arguments.type",
			path:     "./testdata/gcloud-container-invalid-recipe.arguments.type.json",
			expected: serrors.ErrorMismatchBuilderID,
		},
		{
			name:     "mismatch recipe.type",
			path:     "./testdata/gcloud-container-invalid-recipe.type.json",
			expected: serrors.ErrorMismatchBuilderID,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			var builderOpts options.BuilderOpts
			if tt.builderID != "" {
				builderOpts.ExpectedID = &tt.builderID
			}
			outBuilderID, err := prov.VerifyBuilder(&builderOpts)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}

			if err != nil {
				return
			}

			if outBuilderID != tt.builderID {
				t.Errorf(cmp.Diff(outBuilderID, tt.builderID))
			}
		})
	}
}

func Test_VerifySourceURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		source   string
		expected error
	}{
		{
			name:   "valid gcb provenance",
			path:   "./testdata/gcloud-container-github.json",
			source: "https://github.com/laurentsimon/gcb-tests",
		},
		{
			name:     "mismatch name",
			path:     "./testdata/gcloud-container-github.json",
			source:   "https://github.com/laurentsimon/gcb-tests2",
			expected: serrors.ErrorMismatchSource,
		},
		{
			name:     "mismatch org",
			path:     "./testdata/gcloud-container-github.json",
			source:   "https://github.com/wrong/gcb-tests",
			expected: serrors.ErrorMismatchSource,
		},
		{
			name:     "mismatch protocol",
			path:     "./testdata/gcloud-container-github.json",
			source:   "http://github.com/laurentsimon/gcb-tests",
			expected: serrors.ErrorMismatchSource,
		},
		{
			name:     "mismatch full uri",
			path:     "./testdata/gcloud-container-github.json",
			source:   "https://github.com/laurentsimon/gcb-tests/commit/fbbb98765e85ad464302dc5977968104d36e455e",
			expected: serrors.ErrorMismatchSource,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			err = prov.VerifySourceURI(tt.source)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifySignature(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
		},
		{
			name:     "invalid signature",
			path:     "./testdata/gcloud-container-invalid-signature.json",
			expected: serrors.ErrorNoValidSignature,
		},
		{
			name:     "invalid signature",
			path:     "./testdata/gcloud-container-invalid-signature-payloadtype.json",
			expected: serrors.ErrorInvalidDssePayload,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			err = prov.VerifySignature()
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifySubjectDigest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		hash     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
			hash: "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
		},
		{
			name:     "mismatch hash",
			path:     "./testdata/gcloud-container-github.json",
			hash:     "0a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			err = prov.VerifySubjectDigest(tt.hash)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifySummary(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		hash     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
			hash: "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
		},
		{
			name:     "mismatch digest",
			path:     "./testdata/gcloud-container-github.json",
			hash:     "2a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
		},
		{
			name:     "mismatch fuly qualified digest",
			path:     "./testdata/gcloud-container-invalid-fullyqualifieddigest.json",
			hash:     "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			provenanceOpts := options.ProvenanceOpts{
				ExpectedDigest: tt.hash,
			}
			err = prov.VerifySummary(&provenanceOpts)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		hash     string
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
			hash: "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
		},
		{
			name:     "mismatch hash",
			path:     "./testdata/gcloud-container-github.json",
			hash:     "2a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorMismatchHash,
		},
		{
			name:     "invalid kind",
			path:     "./testdata/gcloud-container-invalid-kind.json",
			hash:     "1a033b002f89ed2b8ea733162497fb70f1a4049a7f8602d6a33682b4ad9921fd",
			expected: serrors.ErrorInvalidFormat,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			provenanceOpts := options.ProvenanceOpts{
				ExpectedDigest: tt.hash,
			}
			err = prov.VerifyMetadata(&provenanceOpts)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyTextProvenance(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		alter    bool
		expected error
	}{
		{
			name: "valid gcb provenance",
			path: "./testdata/gcloud-container-github.json",
		},
		{
			name:     "mismatch subject name",
			path:     "./testdata/gcloud-container-github.json",
			alter:    true,
			expected: serrors.ErrorMismatchIntoto,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if !tt.alter {
				err = prov.VerifyTextProvenance()
				if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
					t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
				}
				return
			}

			// Alter fields.
			cpy, err := json.Marshal(prov.verifiedProvenance.Build.UnverifiedTextIntotoStatement)
			if err != nil {
				panic(err)
			}
			chars := map[byte]bool{',': true, ':': true, '[': true, ']': true, '{': true, '}': true, '"': true}
			patch := []byte(strings.Clone(string(cpy)))
			i := 0
			for i < len(patch) {
				// If it's a character that changes the JSON format, ignore it.
				if _, ok := chars[patch[i]]; ok {
					i = i + 1
					fmt.Println("not continue char", string(patch[i:i+10]))
					continue
				}

				ni, ctned := isFieldName(i, patch)
				if !ctned {
					i = ni
					continue
				}

				// Update the string representation.
				if len(patch[i:]) >= 5 && string(patch[i:i+5]) == "false" {
					// Update `false` booleans.
					t := append([]byte("true"), patch[i+5:]...)
					patch = append(patch[:i], t...)
					i += 4
				} else if len(patch[i:]) >= 4 && string(patch[i:i+4]) == "true" {
					// Update `true` booleans.
					t := append([]byte("false"), patch[i+4:]...)
					patch = append(patch[:i], t...)
					i += 5
				} else {
					// Update characters.
					patch[i] += 1
				}

				if err = json.Unmarshal(patch, &prov.verifiedProvenance.Build.UnverifiedTextIntotoStatement); err != nil {
					// If we updated a characters that make a non-string fiel invalid, like Time, unmarshalin will fail,
					// and we ignore the error.
					i += 1
					patch = []byte(strings.Clone(string(cpy)))
					continue
				}
				err = prov.VerifyTextProvenance()
				if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
					t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
				}
				// Start with the original string value.
				patch = []byte(strings.Clone(string(cpy)))
				i += 1
			}
		})
	}
}

func isFieldName(i int, content []byte) (int, bool) {
	j := i
	for j < len(content) {
		if string(content[j]) == "}" ||
			string(content[j]) == "," {
			return i, true
		}
		if string(content[j:j+2]) == "\":" {
			i = j + 2
			return i, false
		}
		j += 1
	}
	return i, true
}

func Test_VerifyBranch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		branch   string
		expected error
	}{
		{
			name:     "valid gcb provenance",
			path:     "./testdata/gcloud-container-github.json",
			branch:   "master",
			expected: serrors.ErrorNotSupported,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			err = prov.VerifyBranch(tt.branch)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		tag      string
		expected error
	}{
		{
			name:     "valid gcb provenance",
			path:     "./testdata/gcloud-container-github.json",
			tag:      "v1.2.3",
			expected: serrors.ErrorNotSupported,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			err = prov.VerifyTag(tt.tag)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}

func Test_VerifyVersionedTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		path     string
		tag      string
		expected error
	}{
		{
			name:     "valid gcb provenance",
			path:     "./testdata/gcloud-container-github.json",
			tag:      "v1.2.3",
			expected: serrors.ErrorNotSupported,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(tt.path)
			if err != nil {
				panic(fmt.Errorf("os.ReadFile: %w", err))
			}

			prov, err := ProvenanceFromBytes(content)
			if err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			if err := setStatement(prov); err != nil {
				panic(fmt.Errorf("ProvenanceFromBytes: %w", err))
			}

			err = prov.VerifyVersionedTag(tt.tag)
			if !cmp.Equal(err, tt.expected, cmpopts.EquateErrors()) {
				t.Errorf(cmp.Diff(err, tt.expected, cmpopts.EquateErrors()))
			}
		})
	}
}
