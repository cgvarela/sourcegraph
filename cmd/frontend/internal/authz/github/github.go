package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/url"
	"time"

	"github.com/sourcegraph/sourcegraph/cmd/frontend/internal/authz"
	"github.com/sourcegraph/sourcegraph/cmd/frontend/types"
	"github.com/sourcegraph/sourcegraph/pkg/api"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc"
	"github.com/sourcegraph/sourcegraph/pkg/extsvc/github"
	"github.com/sourcegraph/sourcegraph/pkg/rcache"
)

type Provider struct {
	client   *github.Client
	codeHost *github.CodeHost
	cacheTTL time.Duration
	cache    pcache
}

func NewProvider(githubURL *url.URL, cacheTTL time.Duration, mockCache pcache) *Provider {
	// Copy-pasta'd from repo-updater/repos/github.go:

	// GitHub.com's API is hosted on api.github.com.
	apiURL, _ := github.APIRoot(githubURL)

	// TODO: how to re-use same cache here as in repo-updater (the last parameter)?
	// TODO: the extsvc.github.Client caches by token, but now we are going to use different tokens
	//   with different requests on the same client, so we need to update its caching logic so that it
	//   uses the proper token for its own cache entries
	client := github.NewClient(apiURL, "", nil)

	p := &Provider{
		codeHost: github.NewCodeHost(githubURL),
		client:   client,
		cache:    mockCache,
		cacheTTL: cacheTTL,
	}
	if p.cache == nil {
		p.cache = rcache.NewWithTTL(fmt.Sprintf("githubAuthz:%s", githubURL.String()), int(math.Ceil(cacheTTL.Seconds())))
	}
	return p
}

// TODO: things to cache
// - list of public repositories (populated per repository)
// - list of repos a user has explicit permissions to

var _ authz.Provider = ((*Provider)(nil))

func (p *Provider) Repos(ctx context.Context, repos map[authz.Repo]struct{}) (mine map[authz.Repo]struct{}, others map[authz.Repo]struct{}) {
	return authz.GetCodeHostRepos(p.codeHost, repos)
}

type cacheVal struct {
	ProjIDs map[string]struct{}
	TTL     time.Duration
}

func githubRepoIDs(repos []*github.Repository) map[string]struct{} {
	ids := make(map[string]struct{})
	for _, repo := range repos {
		ids[repo.ID] = struct{}{}
	}
	return ids
}

func (p *Provider) RepoPerms(ctx context.Context, userAccount *extsvc.ExternalAccount, repos map[authz.Repo]struct{}) (map[api.RepoName]map[authz.Perm]bool, error) {
	var explicitRepos map[string]struct{}
	cachedRepos, cached, err := p.getCachedExplicitRepos(ctx, userAccount)
	if err != nil {
		return nil, err
	}
	if cached {
		explicitRepos = cachedRepos
	} else {
		ghRepos, err := p.fetchUserExplicitRepos(ctx, userAccount)
		if err != nil {
			return nil, err
		}
		ghRepoIDs := githubRepoIDs(ghRepos)
		p.setCachedExplicitRepos(ctx, userAccount, ghRepoIDs)
		explicitRepos = map[string]struct{}{}
		for k := range ghRepoIDs {
			explicitRepos[k] = struct{}{}
		}
	}

	// TODO: public repos

	perms := make(map[api.RepoName]map[authz.Perm]bool)
	providerRepos, _ := p.Repos(ctx, repos)
	for repo := range providerRepos {
		if _, ok := explicitRepos[repo.ExternalRepoSpec.ID]; ok {
			perms[repo.RepoName] = map[authz.Perm]bool{authz.Read: true}
		}
	}
	return perms, nil
}

func (p *Provider) setCachedExplicitRepos(ctx context.Context, userAccount *extsvc.ExternalAccount, ghRepoIDs map[string]struct{}) error {
	// Set cache
	reposB, err := json.Marshal(cacheVal{
		ProjIDs: ghRepoIDs,
		TTL:     p.cacheTTL,
	})
	if err != nil {
		return err
	}
	p.cache.Set(fmt.Sprintf("u:%s", userAccount.AccountID), reposB)
	return nil
}

func (p *Provider) getCachedExplicitRepos(ctx context.Context, userAccount *extsvc.ExternalAccount) (map[string]struct{}, bool, error) {
	reposB, exists := p.cache.Get(fmt.Sprintf("u:%s", userAccount.AccountID))
	if !exists {
		return nil, exists, nil
	}
	var c cacheVal
	if err := json.Unmarshal(reposB, &c); err != nil {
		return nil, false, err
	}
	// TODO: check TTL
	return c.ProjIDs, true, nil
}

func (p *Provider) fetchUserExplicitRepos(ctx context.Context, userAccount *extsvc.ExternalAccount) (repos []*github.Repository, err error) {
	log.Printf("# userAccount: %+v", userAccount)
	_, tok, err := github.GetExternalAccountData(&userAccount.ExternalAccountData)
	if err != nil {
		return nil, err
	}
	if tok == nil || tok.AccessToken == "" {
		return nil, errors.New("no access token found for user")
	}

	for page := 1; ; page++ {
		log.Printf("# %d", page)
		r, hasNextPage, _, err := p.client.ListViewerRepositories(ctx, tok.AccessToken, page)
		if err != nil {
			return nil, err
		}
		log.Printf("# p %d: %+v", page, r)
		repos = append(repos, r...)
		if !hasNextPage {
			break
		}
	}

	return repos, nil
}

func (p *Provider) fetchPublicRepos(ctx context.Context) {
	// TODO: should have an external_repo column in the repo table (similar to how we have external
	// user accounts). This holds the repo metadata (including whether the repo is public).
	// Also need a external_repo_updated column.
	//
	// TODO: should cache at the codehost impl level or here?
}

// FetchAccount always returns nil, because the GitHub API doesn't currently provide a way to fetch user by external SSO account.
func (p *Provider) FetchAccount(ctx context.Context, user *types.User, current []*extsvc.ExternalAccount) (mine *extsvc.ExternalAccount, err error) {
	return nil, nil
}

func (p *Provider) ServiceID() string {
	return p.codeHost.ServiceID()
}

func (p *Provider) ServiceType() string {
	return p.codeHost.ServiceType()
}

func (p *Provider) Validate() (problems []string) {
	// TODO
	return nil
}
