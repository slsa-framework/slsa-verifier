package gha

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"

	serrors "github.com/slsa-framework/slsa-verifier/errors"
)

type searchResult struct {
	resp *entries.SearchLogQueryOK
	err  error
}

type MockEntriesClient struct {
	result searchResult
}

func (m *MockEntriesClient) SearchLogQuery(params *entries.SearchLogQueryParams,
	opts ...entries.ClientOption,
) (*entries.SearchLogQueryOK, error) {
	return m.result.resp, m.result.err
}

func (m *MockEntriesClient) CreateLogEntry(params *entries.CreateLogEntryParams,
	opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return nil, nil
}

func (m *MockEntriesClient) GetLogEntryByIndex(params *entries.GetLogEntryByIndexParams,
	opts ...entries.ClientOption) (*entries.GetLogEntryByIndexOK, error) {
	return nil, nil
}

func (m *MockEntriesClient) GetLogEntryByUUID(params *entries.GetLogEntryByUUIDParams,
	opts ...entries.ClientOption) (*entries.GetLogEntryByUUIDOK, error) {
	return nil, nil
}

func (m *MockEntriesClient) SetTransport(transport runtime.ClientTransport) {
}

func errCmp(e1, e2 error) bool {
	return errors.Is(e1, e2) || errors.Is(e2, e1)
}

func Test_GetRekorEntriesWithCert(t *testing.T) {
	t.Parallel()
	var rekorEntry models.LogEntry

	rekorEntryBytes, err := ioutil.ReadFile("./testdata/rekor-entry-dsse-workflow-inputs.json")
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(rekorEntryBytes, &rekorEntry); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		provenanceRef string
		res           searchResult
		expected      error
	}{
		{
			name:          "missing certificate in provenance",
			provenanceRef: "./testdata/dsse-valid.intoto.jsonl",
			expected:      serrors.ErrorInvalidPEM,
		},
		{
			name:          "bad provenance payload",
			provenanceRef: "./rekor.go",
			expected:      serrors.ErrorInvalidDssePayload,
		},

		{
			name:          "rekor search log query result error",
			provenanceRef: "./testdata/dsse-workflow-inputs.intoto.jsonl",
			res: searchResult{
				err: entries.NewSearchLogQueryDefault(500),
			},
			expected: serrors.ErrorRekorSearch,
		},

		{
			name:          "no rekor entries found",
			provenanceRef: "./testdata/dsse-workflow-inputs.intoto.jsonl",
			res: searchResult{
				err: nil,
				resp: &entries.SearchLogQueryOK{
					Payload: []models.LogEntry{},
				},
			},
			expected: serrors.ErrorRekorSearch,
		},

		{
			name:          "valid rekor entries found",
			provenanceRef: "./testdata/dsse-workflow-inputs.intoto.jsonl",
			res: searchResult{
				err: nil,
				resp: &entries.SearchLogQueryOK{
					Payload: []models.LogEntry{rekorEntry},
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
			mClient.Entries = &MockEntriesClient{result: tt.res}

			provenanceBytes, err := ioutil.ReadFile(tt.provenanceRef)
			if err != nil {
				t.Fatal(err)
			}

			_, err = GetRekorEntriesWithCert(&mClient, []byte(provenanceBytes))
			if !errCmp(err, tt.expected) {
				t.Errorf(cmp.Diff(err, tt.expected))
			}
		})
	}
}
