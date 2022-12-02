package gha

import (
	"errors"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
)

type searchResult struct {
	resp *index.SearchIndexOK
	err  error
}

type MockIndexClient struct {
	result searchResult
}

func (m *MockIndexClient) SearchIndex(params *index.SearchIndexParams,
	opts ...index.ClientOption,
) (*index.SearchIndexOK, error) {
	return m.result.resp, m.result.err
}

func (m *MockIndexClient) SetTransport(transport runtime.ClientTransport) {
}

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func Test_GetRekorEntries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		artifactHash string
		res          searchResult
		expected     error
	}{
		{
			name:         "rekor search result error",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			res: searchResult{
				err: index.NewSearchIndexDefault(500),
			},
			expected: serrors.ErrorRekorSearch,
		},
		{
			name:         "no rekor entries found",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			res: searchResult{
				err: nil,
				resp: &index.SearchIndexOK{
					Payload: []string{},
				},
			},
			expected: serrors.ErrorRekorSearch,
		},
		{
			name:         "valid rekor entries found",
			artifactHash: "0ae7e4fa71686538440012ee36a2634dbaa19df2dd16a466f52411fb348bbc4e",
			res: searchResult{
				err: nil,
				resp: &index.SearchIndexOK{
					Payload: []string{"39d5109436c43dad92897d50f3b271aa456382875a922b28fedef9038b8f683a"},
				},
			},
			expected: nil,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var mClient client.Rekor
			mClient.Index = &MockIndexClient{result: tt.res}

			_, err := getUUIDsByArtifactDigest(&mClient, tt.artifactHash)
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}
