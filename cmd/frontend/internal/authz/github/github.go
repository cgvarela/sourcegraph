package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type pcache interface {
	GetMulti(keys ...string) [][]byte
	SetMulti(keyvals ...[2]string)
	Get(key string) ([]byte, bool)
	Set(key string, b []byte)
	Delete(key string)
}

func NewProvider(githubURL *url.URL, baseToken string, cacheTTL time.Duration, mockCache pcache) *Provider {
	// Copy-pasta'd from repo-updater/repos/github.go:

	// GitHub.com's API is hosted on api.github.com.
	apiURL, _ := github.APIRoot(githubURL)

	// TODO: how to re-use same cache here as in repo-updater (the last parameter)?
	// TODO: the extsvc.github.Client caches by token, but now we are going to use different tokens
	//   with different requests on the same client, so we need to update its caching logic so that it
	//   uses the proper token for its own cache entries
	client := github.NewClient(apiURL, baseToken, nil)

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

type publicRepoCacheVal struct {
	Public bool
	TTL    time.Duration
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

	perms := make(map[api.RepoName]map[authz.Perm]bool) // permissions to return
	// repos to which user doesn't have explicit access
	nonExplicitRepos := map[authz.Repo]struct{}{}
	providerRepos, _ := p.Repos(ctx, repos)
	for repo := range providerRepos {
		if _, ok := explicitRepos[repo.ExternalRepoSpec.ID]; ok {
			perms[repo.RepoName] = map[authz.Perm]bool{authz.Read: true}
		} else {
			nonExplicitRepos[repo] = struct{}{}
		}
	}

	if len(nonExplicitRepos) > 0 {
		publicRepos, err := p.publicRepos(ctx, nonExplicitRepos)
		if err != nil {
			return nil, err
		}
		for repo := range nonExplicitRepos {
			if publicRepos[repo.ExternalRepoSpec.ID] {
				perms[repo.RepoName] = map[authz.Perm]bool{authz.Read: true}
			}
		}
	}

	return perms, nil
}

func (p *Provider) publicRepos(ctx context.Context, repos map[authz.Repo]struct{}) (map[string]bool, error) {
	cachedIsPublic, err := p.getCachedPublicRepos(ctx, repos)
	if err != nil {
		return nil, err
	}
	if len(cachedIsPublic) >= len(repos) {
		return cachedIsPublic, nil
	}

	missing := make(map[string]struct{})
	for r := range repos {
		if _, ok := cachedIsPublic[r.ExternalRepoSpec.ID]; !ok {
			missing[r.ExternalRepoSpec.ID] = struct{}{}
		}
	}

	missingIsPublic, err := p.fetchPublicRepos(ctx, missing)
	if err != nil {
		return nil, err
	}
	p.setCachedPublicRepos(ctx, missingIsPublic)

	for k, v := range missingIsPublic {
		cachedIsPublic[k] = v
	}
	return cachedIsPublic, nil
}

func (p *Provider) setCachedPublicRepos(ctx context.Context, isPublic map[string]bool) error {
	setArgs := make([][2]string, 0, 2*len(isPublic))
	for k, v := range isPublic {
		key := fmt.Sprintf("r:%s", k)
		val, err := json.Marshal(publicRepoCacheVal{
			Public: v,
			TTL:    p.cacheTTL,
		})
		if err != nil {
			return err
		}
		setArgs = append(setArgs, [2]string{key, string(val)})
	}
	p.cache.SetMulti(setArgs...)
	return nil
}

func (p *Provider) getCachedPublicRepos(ctx context.Context, repos map[authz.Repo]struct{}) (isPublic map[string]bool, err error) {
	if len(repos) == 0 {
		return nil, nil
	}
	isPublic = make(map[string]bool)
	repoList := make([]string, 0, len(repos))
	getArgs := make([]string, 0, len(repos))
	for r := range repos {
		getArgs = append(getArgs, fmt.Sprintf("r:%s", r))
		repoList = append(repoList, r.ExternalRepoSpec.ID)
	}
	vals := p.cache.GetMulti(getArgs...)
	if len(vals) != len(repos) {
		return nil, fmt.Errorf("number of cache items did not match number of keys")
	}

	for i, v := range vals {
		if v == nil {
			continue
		}
		var val publicRepoCacheVal
		if err := json.Unmarshal(v, &val); err != nil {
			return nil, err
		}
		isPublic[repoList[i]] = val.Public
	}

	return isPublic, nil
}

// fetchPublicRepos returns a map where the keys are GitHub repository node IDs and the values are booleans
// indicating whether a repository is public (true) or private (false).
func (p *Provider) fetchPublicRepos(ctx context.Context, repos map[string]struct{}) (map[string]bool, error) {
	isPublic := make(map[string]bool)
	for ghRepoID := range repos {
		ghRepo, err := p.client.GetRepositoryByNodeID(ctx, ghRepoID)
		if err != nil {
			return nil, err
		}
		isPublic[ghRepoID] = !ghRepo.IsPrivate
	}
	return isPublic, nil
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
	_, tok, err := github.GetExternalAccountData(&userAccount.ExternalAccountData)
	if err != nil {
		return nil, err
	}
	if tok == nil || tok.AccessToken == "" {
		return nil, errors.New("no access token found for user")
	}

	for page := 1; ; page++ {
		r, hasNextPage, _, err := p.client.ListViewerRepositories(ctx, tok.AccessToken, page)
		if err != nil {
			return nil, err
		}
		repos = append(repos, r...)
		if !hasNextPage {
			break
		}
	}

	return repos, nil
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
