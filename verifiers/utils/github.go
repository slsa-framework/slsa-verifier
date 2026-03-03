package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// TagResolver resolves a commit SHA to the tags that point to it.
type TagResolver interface {
	TagsForCommitSHA(ctx context.Context, owner, repo, sha string) ([]string, error)
}

// GitHubTagResolver resolves tags by querying the GitHub REST API.
type GitHubTagResolver struct {
	HTTPClient *http.Client
	Token      string // optional, for authenticated requests
}

type ghTag struct {
	Name   string `json:"name"`
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
}

func (r *GitHubTagResolver) TagsForCommitSHA(ctx context.Context, owner, repo, sha string) ([]string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/tags?per_page=100", owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building GitHub tags request for %s/%s: %w", owner, repo, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}

	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching GitHub tags for %s/%s: %w", owner, repo, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d for %s/%s", resp.StatusCode, owner, repo)
	}

	var tags []ghTag
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, fmt.Errorf("decoding GitHub tags response for %s/%s: %w", owner, repo, err)
	}

	var names []string
	for _, t := range tags {
		if t.Commit.SHA == sha {
			names = append(names, t.Name)
		}
	}
	return names, nil
}
