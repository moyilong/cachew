package strategy

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/errors"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/httputil"
	"github.com/block/cachew/internal/spool"
	"github.com/block/cachew/internal/strategy/handler"
)

// RegisterNuGet registers the NuGet v3 feed strategy so restores can use the shared cache.
func RegisterNuGet(r *Registry, spools spool.Provider) {
	Register(r, "nuget", "Caches public NuGet v3 feeds.", func(ctx context.Context, config NuGetConfig, c cache.Cache, mux Mux) (*NuGet, error) {
		registry, err := spools()
		if err != nil {
			return nil, errors.Wrap(err, "create spool registry")
		}
		return NewNuGet(ctx, config, c, mux, registry)
	})
}

// NuGetConfig identifies the feed and its public address so advertised resources stay behind the proxy.
type NuGetConfig struct {
	Upstream        string        `hcl:"upstream,optional" help:"Public NuGet v3 service index URL." default:"https://api.nuget.org/v3/index.json"`
	PublicURL       string        `hcl:"public-url,optional" help:"Client-facing absolute URL of the /nuget route." default:"${CACHEW_URL}/nuget"`
	MetadataTTL     time.Duration `hcl:"metadata-ttl,optional" help:"Cache TTL for version lists, registration, search and audit metadata." default:"5m"`
	ResourceOrigins []string      `hcl:"resource-origins,optional" help:"Additional trusted HTTP(S) origins for custom feeds and redirects; nuget.org HTTPS subdomains are trusted for the official feed."`
}

// NuGet keeps NuGet v3 resource links behind the cache, including links inside registration and audit metadata.
type NuGet struct {
	upstream    *url.URL
	publicURL   string
	origins     map[string]bool
	nugetOrg    bool
	metadataTTL time.Duration
	handler     http.Handler
}

var _ Strategy = (*NuGet)(nil)

// NewNuGet mounts a read-only, anonymous feed at /nuget/index.json with shared artifact caching.
func NewNuGet(_ context.Context, config NuGetConfig, c cache.Cache, mux Mux, spools *spool.Registry) (*NuGet, error) {
	upstream, err := parseNuGetURL(cmp.Or(config.Upstream, "https://api.nuget.org/v3/index.json"))
	if err != nil {
		return nil, errors.Wrap(err, "invalid NuGet upstream")
	}
	publicURL, err := parseNuGetURL(config.PublicURL)
	if err != nil {
		return nil, errors.Wrap(err, "invalid NuGet public-url")
	}
	publicURL = publicURL.JoinPath()
	if config.MetadataTTL <= 0 {
		return nil, errors.New("NuGet metadata-ttl must be positive")
	}
	n := &NuGet{
		upstream: upstream, publicURL: strings.TrimRight(publicURL.String(), "/"),
		origins:     map[string]bool{upstream.Scheme + "://" + upstream.Host: true},
		nugetOrg:    upstream.Scheme == schemeHTTPS && upstream.Host == "api.nuget.org",
		metadataTTL: config.MetadataTTL,
	}
	if n.nugetOrg {
		n.origins["https://nuget.azure.cn"] = true
	}
	for _, raw := range config.ResourceOrigins {
		origin, parseErr := parseNuGetURL(raw)
		if parseErr != nil || (origin.Path != "" && origin.Path != "/") {
			return nil, errors.Errorf("invalid NuGet resource origin %q: expected an HTTP(S) origin without a path", raw)
		}
		n.origins[origin.Scheme+"://"+origin.Host] = true
	}
	client := &http.Client{Transport: &nugetTransport{nuget: n, base: http.DefaultTransport}}
	n.handler = handler.New(client, c, spools).Metrics("nuget", upstream.Hostname()).
		CacheKey(func(r *http.Request) string {
			if nugetArtifact(r.URL.Path) {
				return r.URL.String()
			}
			return n.publicURL + "\n" + r.URL.String()
		}).
		TTL(func(r *http.Request) time.Duration {
			if nugetArtifact(r.URL.Path) {
				return 0
			}
			return n.metadataTTL
		}).
		Transform(func(r *http.Request) (*http.Request, error) {
			req, reqErr := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
			return req, errors.Wrap(reqErr, "create NuGet upstream request")
		})
	mux.Handle("GET /nuget/{path...}", n)
	return n, nil
}

// String identifies the upstream feed in strategy diagnostics.
func (n *NuGet) String() string { return "nuget:" + n.upstream.Host }

func nugetArtifact(path string) bool {
	return strings.HasSuffix(path, ".nupkg") || strings.HasSuffix(path, ".nuspec")
}

// ServeHTTP validates resource destinations before cache lookup to keep the feed from becoming an open proxy.
func (n *NuGet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "NuGet mirror is read-only", http.StatusMethodNotAllowed)
		return
	}
	target, err := n.targetURL(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r = r.Clone(r.Context())
	r.URL = target
	r.Header.Del("Accept-Encoding")
	r.Header.Del("Authorization")
	r.Header.Del("Cookie")
	n.handler.ServeHTTP(w, r)
}

func parseNuGetURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.Errorf("expected an HTTP(S) URL without credentials, query or fragment: %q", raw)
	}
	if err := httputil.ValidatePath(u.Path); err != nil {
		return nil, errors.Wrap(err, "validate NuGet URL path")
	}
	return u, nil
}

func (n *NuGet) targetURL(r *http.Request) (*url.URL, error) {
	if err := httputil.ValidatePath(r.URL.Path); err != nil {
		return nil, errors.Wrap(err, "validate NuGet resource path")
	}
	if r.URL.Path == "/nuget/index.json" {
		u := *n.upstream
		u.RawQuery = r.URL.RawQuery
		return &u, nil
	}
	scheme, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.EscapedPath(), "/nuget/"), "/")
	if !ok {
		return nil, errors.New("invalid NuGet resource path")
	}
	u, err := url.Parse(scheme + "://" + rest)
	if err != nil || !n.allows(u) {
		return nil, errors.New("untrusted NuGet resource origin")
	}
	u.RawQuery = r.URL.RawQuery
	return u, nil
}

func (n *NuGet) allows(u *url.URL) bool {
	if u.User != nil || u.Opaque != "" || u.Fragment != "" {
		return false
	}
	return n.origins[u.Scheme+"://"+u.Host] || (n.nugetOrg && u.Scheme == schemeHTTPS && u.Port() == "" &&
		(u.Host == "nuget.org" || strings.HasSuffix(u.Host, ".nuget.org")))
}

type nugetTransport struct {
	nuget *NuGet
	base  http.RoundTripper
}

// RoundTrip checks every redirect and rewrites metadata before the shared handler commits it to the cache.
func (t *nugetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !t.nuget.allows(r.URL) {
		return nil, errors.New("untrusted NuGet redirect origin")
	}
	r = r.Clone(r.Context())
	r.Header = make(http.Header)
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, errors.Wrap(err, "fetch NuGet resource")
	}
	if resp.StatusCode != http.StatusOK || (!strings.Contains(resp.Header.Get("Content-Type"), "json") &&
		!strings.HasSuffix(r.URL.Path, ".json")) {
		return resp, nil
	}
	if r.Method == http.MethodHead {
		resp.Header.Del("Content-Length")
		resp.Header.Del("ETag")
		resp.ContentLength = -1
		return resp, nil
	}
	defer resp.Body.Close()
	body, err := t.nuget.rewriteResponse(resp)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Cache-Control", "max-age="+strconv.FormatInt(int64(t.nuget.metadataTTL.Seconds()), 10))
	for _, header := range []string{"Content-Encoding", "ETag", "Last-Modified", "Content-MD5", "Digest", "Accept-Ranges"} {
		resp.Header.Del(header)
	}
	return resp, nil
}

func (n *NuGet) rewriteResponse(resp *http.Response) ([]byte, error) {
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, errors.Wrap(err, "decode NuGet gzip response")
		}
		defer gz.Close()
		reader = gz
	}
	const maxMetadataSize = 64 << 20
	body, err := io.ReadAll(io.LimitReader(reader, maxMetadataSize+1))
	if err != nil {
		return nil, errors.Wrap(err, "read NuGet metadata")
	}
	if len(body) > maxMetadataSize {
		return nil, errors.New("NuGet metadata exceeds 64 MiB")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.Wrap(err, "decode NuGet metadata")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after NuGet metadata")
	}
	if object, ok := value.(map[string]any); ok {
		if resources, hasResources := object["resources"].([]any); hasResources {
			filtered := make([]any, 0, len(resources))
			for _, resource := range resources {
				entry, _ := resource.(map[string]any)
				kind, _ := entry["@type"].(string)
				if !strings.HasPrefix(kind, "PackagePublish/") && !strings.HasPrefix(kind, "SymbolPackagePublish/") {
					filtered = append(filtered, resource)
				}
			}
			object["resources"] = filtered
		}
	}
	n.rewriteLinks(value)
	body, err = json.Marshal(value)
	return body, errors.Wrap(err, "encode NuGet metadata")
}

func (n *NuGet) rewriteLinks(value any) {
	switch value := value.(type) {
	case []any:
		for _, item := range value {
			n.rewriteLinks(item)
		}
	case map[string]any:
		for key, item := range value {
			switch key {
			case "@id", "packageContent", "registration", "catalogEntry", "url", "readmeUrl", "iconUrl", "licenseUrl":
				if raw, ok := item.(string); ok {
					u, err := url.Parse(raw)
					if err == nil && n.allows(u) {
						suffix := strings.TrimPrefix(raw, u.Scheme+"://"+u.Host)
						if !strings.HasPrefix(suffix, "/") {
							suffix = "/" + suffix
						}
						value[key] = n.publicURL + "/" + u.Scheme + "/" + u.Host + suffix
					}
				}
			}
			if key != "@context" {
				n.rewriteLinks(item)
			}
		}
	}
}
