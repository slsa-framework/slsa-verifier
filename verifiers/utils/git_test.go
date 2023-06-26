package utils

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func Test_NormalizeGitURI(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "empty uri",
			uri:      "",
			expected: "git+https://",
		},
		{
			name:     "https scheme",
			uri:      "https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
			expected: "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
		},
		{
			name:     "http scheme",
			uri:      "http://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
			expected: "git+http://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
		},
		{
			name:     "git+https scheme",
			uri:      "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
			expected: "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
		},
		{
			name:     "no scheme",
			uri:      "github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
			expected: "git+https://github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
		},
		{
			name:     "git+ scheme",
			uri:      "git+github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
			expected: "git+github.com/kubernetes/kubernetes@refs/tags/v1.0.0",
		},
		{
			name:     "https scheme no ref",
			uri:      "https://github.com/kubernetes/kubernetes",
			expected: "git+https://github.com/kubernetes/kubernetes",
		},
		{
			name:     "http scheme no ref",
			uri:      "http://github.com/kubernetes/kubernetes",
			expected: "git+http://github.com/kubernetes/kubernetes",
		},
		{
			name:     "git+https scheme no ref",
			uri:      "git+https://github.com/kubernetes/kubernetes",
			expected: "git+https://github.com/kubernetes/kubernetes",
		},
		{
			name:     "no scheme no ref",
			uri:      "github.com/kubernetes/kubernetes",
			expected: "git+https://github.com/kubernetes/kubernetes",
		},
		{
			name:     "git+ scheme no ref",
			uri:      "git+github.com/kubernetes/kubernetes",
			expected: "git+github.com/kubernetes/kubernetes",
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, want := NormalizeGitURI(tt.uri), tt.expected; got != want {
				t.Errorf("unexpected value, got: %q, want: %q", got, want)
			}
		})
	}
}

func Test_ParseGitURIAndRef(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		uri         string
		expectedURI string
		expectedRef string
		err         error
	}{
		{
			name: "empty uri",
			uri:  "",
			err:  serrors.ErrorMalformedURI,
		},
		{
			name: "no scheme with ref",
			uri:  "github.com/kubernetes/kubernetes@v1.0.0",
			err:  serrors.ErrorMalformedURI,
		},
		{
			name: "https scheme with ref",
			uri:  "https://github.com/kubernetes/kubernetes@v1.0.0",
			err:  serrors.ErrorMalformedURI,
		},
		{
			name:        "git+https scheme with ref",
			uri:         "git+https://github.com/kubernetes/kubernetes@v1.0.0",
			expectedURI: "git+https://github.com/kubernetes/kubernetes",
			expectedRef: "v1.0.0",
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			uri, ref, err := ParseGitURIAndRef(tt.uri)
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error: %v", err)
			}

			if want, got := tt.expectedURI, uri; got != want {
				t.Fatalf("unexpected uri, got: %q, want: %q", got, want)
			}

			if want, got := tt.expectedRef, ref; got != want {
				t.Fatalf("unexpected ref, got: %q, want: %q", got, want)
			}
		})
	}
}

func Test_ParseGitRef(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		ref          string
		expectedType string
		expectedRef  string
	}{
		{
			name:         "empty ref",
			ref:          "",
			expectedType: "",
			expectedRef:  "",
		},
		{
			name:         "no type ",
			ref:          "v1.0.0",
			expectedType: "",
			expectedRef:  "v1.0.0",
		},
		{
			name:         "no type with slash",
			ref:          "tags/v1.0.0",
			expectedType: "",
			expectedRef:  "tags/v1.0.0",
		},
		{
			name:         "type without slash",
			ref:          "refs/mytype/v1.0.0",
			expectedType: "mytype",
			expectedRef:  "v1.0.0",
		},
		{
			name:         "type with slash",
			ref:          "refs/mytype/feat/v1.0.0",
			expectedType: "mytype",
			expectedRef:  "feat/v1.0.0",
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			typ, ref := ParseGitRef(tt.ref)
			if want, got := tt.expectedType, typ; got != want {
				t.Fatalf("unexpected type, got: %q, want: %q", got, want)
			}

			if want, got := tt.expectedRef, ref; got != want {
				t.Fatalf("unexpected ref, got: %q, want: %q", got, want)
			}
		})
	}
}

func Test_ValidateGitRef(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		ref         string
		typ         string
		expectedRef string
		err         error
	}{
		{
			name: "empty ref",
			ref:  "",
			typ:  "",
			err:  serrors.ErrorInvalidRef,
		},
		{
			name:        "no type ",
			ref:         "v1.0.0",
			typ:         "",
			expectedRef: "v1.0.0",
		},
		{
			name:        "no type with slash",
			ref:         "tags/v1.0.0",
			typ:         "",
			expectedRef: "tags/v1.0.0",
		},
		{
			name:        "type without slash",
			ref:         "refs/mytype/v1.0.0",
			typ:         "mytype",
			expectedRef: "v1.0.0",
		},
		{
			name: "mismatch type",
			ref:  "refs/mytype/v1.0.0",
			typ:  "tags",
			err:  serrors.ErrorInvalidRef,
		},
		{
			name:        "type with slash",
			ref:         "refs/mytype/feat/v1.0.0",
			typ:         "mytype",
			expectedRef: "feat/v1.0.0",
		},
		{
			name: "mismatch type with slash",
			ref:  "refs/mytype/feat/v1.0.0",
			typ:  "tags",
			err:  serrors.ErrorInvalidRef,
		},
	}

	for i := range testCases {
		tt := testCases[i]
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ref, err := ValidateGitRef(tt.typ, tt.ref)
			if diff := cmp.Diff(tt.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("unexpected error: %v", err)
			}

			if want, got := tt.expectedRef, ref; got != want {
				t.Fatalf("unexpected ref, got: %q, want: %q", got, want)
			}
		})
	}
}
