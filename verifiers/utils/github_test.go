package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestGitHubTagResolver_TagsForCommitSHA(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		sha          string
		serverTags   []ghTag
		statusCode   int
		expectedTags []string
		wantErr      bool
	}{
		{
			name: "SHA matches one tag",
			sha:  "abc0123456789abcdef0123456789abcdef01234",
			serverTags: []ghTag{
				{Name: "v1.2.3", Commit: struct{ SHA string `json:"sha"` }{SHA: "abc0123456789abcdef0123456789abcdef01234"}},
				{Name: "v1.2.2", Commit: struct{ SHA string `json:"sha"` }{SHA: "0000000000000000000000000000000000000000"}},
			},
			expectedTags: []string{"v1.2.3"},
		},
		{
			name: "SHA matches multiple tags",
			sha:  "abc0123456789abcdef0123456789abcdef01234",
			serverTags: []ghTag{
				{Name: "v1.2.3", Commit: struct{ SHA string `json:"sha"` }{SHA: "abc0123456789abcdef0123456789abcdef01234"}},
				{Name: "v1.2.3-rc1", Commit: struct{ SHA string `json:"sha"` }{SHA: "abc0123456789abcdef0123456789abcdef01234"}},
			},
			expectedTags: []string{"v1.2.3", "v1.2.3-rc1"},
		},
		{
			name: "SHA matches no tags",
			sha:  "abc0123456789abcdef0123456789abcdef01234",
			serverTags: []ghTag{
				{Name: "v1.2.3", Commit: struct{ SHA string `json:"sha"` }{SHA: "0000000000000000000000000000000000000000"}},
			},
			expectedTags: nil,
		},
		{
			name:       "non-200 response returns error",
			sha:        "abc0123456789abcdef0123456789abcdef01234",
			statusCode: http.StatusForbidden,
			wantErr:    true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			statusCode := http.StatusOK
			if tt.statusCode != 0 {
				statusCode = tt.statusCode
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
				if statusCode == http.StatusOK {
					_ = json.NewEncoder(w).Encode(tt.serverTags)
				}
			}))
			t.Cleanup(server.Close)

			// Use a custom HTTPClient with a transport that redirects to our test server,
			// since GitHubTagResolver uses the real GitHub URL.
			resolver := &GitHubTagResolver{
				HTTPClient: &http.Client{
					Transport: &hostOverrideTransport{
						base:    server.Client().Transport,
						baseURL: server.URL,
					},
				},
			}

			tags, err := resolver.TagsForCommitSHA(context.Background(), "owner", "repo", tt.sha)
			if (err != nil) != tt.wantErr {
				t.Fatalf("TagsForCommitSHA() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if diff := cmp.Diff(tt.expectedTags, tags, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("unexpected tags (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// hostOverrideTransport redirects all requests to baseURL, preserving the path.
type hostOverrideTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (t *hostOverrideTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	override, err := http.NewRequest(req.Method, t.baseURL+req.URL.Path+"?"+req.URL.RawQuery, req.Body)
	if err != nil {
		return nil, err
	}
	override.Header = req.Header
	rt := t.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(override)
}
