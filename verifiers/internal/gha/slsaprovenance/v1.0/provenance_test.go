package v1

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func Test_verifySourceURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name              string
		resolvedDeps      []slsa1.ResourceDescriptor
		expectedSourceURI string
		err               error
	}{
		{
			name:         "missing resolved dependencies",
			resolvedDeps: nil,
			err:          serrors.ErrorInvalidDssePayload,
		},
		{
			name: "single resolved dependencies",
			resolvedDeps: []slsa1.ResourceDescriptor{
				{URI: "git+https://github.com/some/repo"},
			},
			expectedSourceURI: "git+https://github.com/some/repo",
		},
		{
			name: "multiple resolved dependencies, no annotation",
			resolvedDeps: []slsa1.ResourceDescriptor{
				{URI: "git+https://github.com/some/repo"},
				{URI: "git+https://github.com/some/other"},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "first resolved dependencies with source annotation",
			resolvedDeps: []slsa1.ResourceDescriptor{
				{
					URI: "git+https://github.com/some/repo",
					Annotations: map[string]interface{}{
						"source": string("true"),
					},
				},
				{
					URI: "git+https://github.com/some/other",
				},
			},
			expectedSourceURI: "git+https://github.com/some/repo",
		},
		{
			name: "second resolved dependencies with source annotation",
			resolvedDeps: []slsa1.ResourceDescriptor{
				{
					URI: "git+https://github.com/some/repo",
				},
				{
					URI: "git+https://github.com/some/other",
					Annotations: map[string]interface{}{
						"source": string("true"),
					},
				},
			},
			expectedSourceURI: "git+https://github.com/some/other",
		},
		{
			name: "bad source annotation value",
			resolvedDeps: []slsa1.ResourceDescriptor{
				{
					URI: "git+https://github.com/some/repo",
				},
				{
					URI: "git+https://github.com/some/other",
					Annotations: map[string]interface{}{
						"source": 64,
					},
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "source annotation value false",
			resolvedDeps: []slsa1.ResourceDescriptor{
				{
					URI: "git+https://github.com/some/repo",
				},
				{
					URI: "git+https://github.com/some/other",
					Annotations: map[string]interface{}{
						"source": "false",
					},
				},
			},
			err: serrors.ErrorInvalidDssePayload,
		},
		{
			name: "second resolved dependencies with two source annotation",
			resolvedDeps: []slsa1.ResourceDescriptor{
				{
					URI: "git+https://github.com/some/repo",
					Annotations: map[string]interface{}{
						"source": string("false"),
					},
				},
				{
					URI: "git+https://github.com/some/other",
					Annotations: map[string]interface{}{
						"source": string("true"),
					},
				},
			},
			expectedSourceURI: "git+https://github.com/some/other",
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			prov1 := &ProvenanceV1{
				Predicate: slsa1.ProvenancePredicate{
					BuildDefinition: slsa1.ProvenanceBuildDefinition{
						ResolvedDependencies: tt.resolvedDeps,
					},
				},
			}

			sourceURI, err := prov1.SourceURI()
			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}
			if tt.err == nil {
				if sourceURI != tt.expectedSourceURI {
					t.Errorf("expected source URI %s got %s", tt.expectedSourceURI, sourceURI)
				}
			}
		})
	}
}
