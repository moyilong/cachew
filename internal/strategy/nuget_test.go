package strategy_test

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/alecthomas/hcl/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/spool"
	"github.com/block/cachew/internal/strategy"
)

func newNuGetTest(t *testing.T, upstream string, origins ...string) (*http.ServeMux, cache.Cache) {
	t.Helper()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	c, err := cache.NewMemory(ctx, cache.MemoryConfig{MaxTTL: time.Hour})
	assert.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	mux := http.NewServeMux()
	_, err = strategy.NewNuGet(ctx, strategy.NuGetConfig{
		Upstream: upstream, PublicURL: "https://cache.example/nuget", MetadataTTL: time.Minute, ResourceOrigins: origins,
	}, c, mux, newTestSpools(t))
	assert.NoError(t, err)
	return mux, c
}

func nugetRequest(t *testing.T, mux http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	r := httptest.NewRequestWithContext(ctx, method, target, nil)
	r.Header.Set("Authorization", "Bearer client-secret")
	r.Header.Set("Cookie", "session=private")
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func nugetResourceURL(raw string) string {
	return "https://cache.example/nuget/" + strings.Replace(raw, "://", "/", 1)
}

func TestNuGetFeed(t *testing.T) {
	var packageCalls, indexCalls, searchCalls atomic.Int32
	search := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		searchCalls.Add(1)
		assert.Equal(t, "a+b", r.URL.Query().Get("q"))
		assert.Equal(t, "true", r.URL.Query().Get("semVerLevel"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalHits":9007199254740993,"data":[]}`))
	}))
	defer search.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "", r.Header.Get("Authorization"))
		assert.Equal(t, "", r.Header.Get("Cookie"))
		base := "http://" + r.Host
		switch r.URL.Path {
		case "/v3/index.json":
			indexCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "3.0.0", "resources": []any{
				map[string]string{"@id": base + "/v3-flatcontainer/", "@type": "PackageBaseAddress/3.0.0"},
				map[string]string{"@id": search.URL + "/query", "@type": "SearchQueryService/3.5.0"},
				map[string]string{"@id": base + "/registration/{id-lower}/{version-lower}.json", "@type": "PackageVersionDisplayMetadataUriTemplate/3.0.0-rc"},
				map[string]string{"@id": base + "/push", "@type": "PackagePublish/2.0.0"},
			}})
		case "/registration/foo/index.json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("ETag", `"upstream"`)
			gz := gzip.NewWriter(w)
			_ = json.NewEncoder(gz).Encode(map[string]any{"items": []any{
				map[string]string{"packageContent": base + "/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg",
					"projectUrl": "https://example.com/project", "description": "See " + base + "/docs"},
			}, "@context": map[string]string{"@id": base + "/schema"}})
			_ = gz.Close()
		case "/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg":
			packageCalls.Add(1)
			_, _ = w.Write([]byte("package"))
		case "/vulnerabilities/index.json":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"@id": "base", "url": base + "/vulnerabilities/base.json"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	mux, _ := newNuGetTest(t, upstream.URL+"/v3/index.json", search.URL)

	index := nugetRequest(t, mux, http.MethodGet, "/nuget/index.json")
	assert.Equal(t, http.StatusOK, index.Code)
	var feed struct {
		Resources []map[string]string `json:"resources"`
	}
	assert.NoError(t, json.Unmarshal(index.Body.Bytes(), &feed))
	assert.Equal(t, 3, len(feed.Resources))
	assert.Equal(t, nugetResourceURL(upstream.URL+"/v3-flatcontainer/"), feed.Resources[0]["@id"])
	assert.Equal(t, nugetResourceURL(upstream.URL+"/registration/{id-lower}/{version-lower}.json"), feed.Resources[2]["@id"])
	assert.Equal(t, index.Body.String(), nugetRequest(t, mux, http.MethodGet, "/nuget/index.json").Body.String())
	assert.Equal(t, int32(1), indexCalls.Load())

	for range 2 {
		response := nugetRequest(t, mux, http.MethodGet, feed.Resources[0]["@id"]+"foo/1.0.0/foo.1.0.0.nupkg")
		assert.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, "package", response.Body.String())
	}
	assert.Equal(t, int32(1), packageCalls.Load())
	for range 2 {
		response := nugetRequest(t, mux, http.MethodGet, feed.Resources[1]["@id"]+"?q=a%2Bb&semVerLevel=true")
		assert.Equal(t, http.StatusOK, response.Code)
		assert.Contains(t, response.Body.String(), "9007199254740993")
	}
	assert.Equal(t, int32(1), searchCalls.Load())

	registration := nugetRequest(t, mux, http.MethodGet, nugetResourceURL(upstream.URL+"/registration/foo/index.json"))
	assert.Equal(t, http.StatusOK, registration.Code)
	assert.Contains(t, registration.Body.String(), nugetResourceURL(upstream.URL+"/v3-flatcontainer/foo/1.0.0/foo.1.0.0.nupkg"))
	assert.Contains(t, registration.Body.String(), "https://example.com/project")
	assert.Contains(t, registration.Body.String(), "See "+upstream.URL+"/docs")
	assert.Contains(t, registration.Body.String(), upstream.URL+"/schema")
	assert.Equal(t, "", registration.Header().Get("Content-Encoding"))
	assert.Equal(t, strconv.Itoa(registration.Body.Len()), registration.Header().Get("Content-Length"))
	assert.NotEqual(t, `"upstream"`, registration.Header().Get("ETag"))
	audit := nugetRequest(t, mux, http.MethodGet, nugetResourceURL(upstream.URL+"/vulnerabilities/index.json"))
	assert.Equal(t, http.StatusOK, audit.Code)
	assert.Contains(t, audit.Body.String(), nugetResourceURL(upstream.URL+"/vulnerabilities/base.json"))
}

func TestNuGetRejectsUnsafeRequests(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	mux, _ := newNuGetTest(t, upstream.URL+"/index.json")
	u, err := url.Parse(upstream.URL)
	assert.NoError(t, err)
	for _, path := range []string{
		"/nuget/http/evil.example/file.nupkg",
		"/nuget/http/" + u.Host + "%2F.evil.example/file.nupkg",
		"/nuget/http/user@" + u.Host + "/file.nupkg",
		"/nuget/http/" + u.Host + "/%2e%2e/secret",
		"/nuget/http/" + u.Host + "/%2e%2e%2fsecret",
		"/nuget/http/" + u.Host + "/a%5cb",
		"/nuget/file/" + u.Host + "/file.nupkg",
		"/nuget/invalid",
	} {
		t.Run(path, func(t *testing.T) {
			response := nugetRequest(t, mux, http.MethodGet, path)
			assert.Equal(t, http.StatusBadRequest, response.Code)
		})
	}
	response := nugetRequest(t, mux, http.MethodPut, "/nuget/index.json")
	assert.Equal(t, http.StatusMethodNotAllowed, response.Code)
	assert.Equal(t, int32(0), calls.Load())
}

func TestNuGetDoesNotCacheErrors(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusOK} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("not JSON"))
			}))
			defer upstream.Close()
			mux, _ := newNuGetTest(t, upstream.URL+"/index.json")
			for range 2 {
				response := nugetRequest(t, mux, http.MethodGet, "/nuget/index.json")
				if status == http.StatusOK {
					assert.Equal(t, http.StatusBadGateway, response.Code)
				} else {
					assert.Equal(t, status, response.Code)
					assert.Equal(t, "60", response.Header().Get("Retry-After"))
				}
			}
			assert.Equal(t, int32(2), calls.Load())
		})
	}
}

func TestNuGetRedirects(t *testing.T) {
	var calls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("package"))
	}))
	defer destination.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/package.nupkg", http.StatusFound)
	}))
	defer upstream.Close()
	for _, allowed := range []bool{false, true} {
		t.Run(strconv.FormatBool(allowed), func(t *testing.T) {
			var origins []string
			if allowed {
				origins = append(origins, destination.URL)
			}
			mux, _ := newNuGetTest(t, upstream.URL+"/index.json", origins...)
			response := nugetRequest(t, mux, http.MethodGet, nugetResourceURL(upstream.URL+"/package.nupkg"))
			if allowed {
				assert.Equal(t, http.StatusOK, response.Code)
				assert.Equal(t, "package", response.Body.String())
			} else {
				assert.Equal(t, http.StatusBadGateway, response.Code)
				assert.Equal(t, int32(0), calls.Load())
			}
		})
	}
}

func TestNuGetMetadataExpiresBeforePackages(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasSuffix(r.URL.Path, ".json") {
			_, _ = w.Write([]byte(`{"versions":["1.0.0"]}`))
		} else {
			_, _ = w.Write([]byte("package"))
		}
	}))
	defer upstream.Close()
	_, c := newNuGetTest(t, upstream.URL+"/index.json")
	mux := http.NewServeMux()
	_, err := strategy.NewNuGet(t.Context(), strategy.NuGetConfig{
		Upstream: upstream.URL + "/index.json", PublicURL: "https://cache.example/nuget", MetadataTTL: 50 * time.Millisecond,
	}, c, mux, newTestSpools(t))
	assert.NoError(t, err)
	for range 2 {
		assert.Equal(t, http.StatusOK, nugetRequest(t, mux, http.MethodGet, "/nuget/index.json").Code)
		assert.Equal(t, http.StatusOK, nugetRequest(t, mux, http.MethodGet, nugetResourceURL(upstream.URL+"/package.nupkg")).Code)
	}
	assert.Equal(t, int32(2), calls.Load())
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, http.StatusOK, nugetRequest(t, mux, http.MethodGet, "/nuget/index.json").Code)
	assert.Equal(t, http.StatusOK, nugetRequest(t, mux, http.MethodGet, nugetResourceURL(upstream.URL+"/package.nupkg")).Code)
	assert.Equal(t, int32(3), calls.Load())
}

func TestNuGetHeadAndRange(t *testing.T) {
	var downloads atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "7")
		if r.Method == http.MethodHead {
			return
		}
		downloads.Add(1)
		_, _ = io.WriteString(w, "package")
	}))
	defer upstream.Close()
	mux, _ := newNuGetTest(t, upstream.URL+"/index.json")
	resource := nugetResourceURL(upstream.URL + "/package.nupkg")
	head := nugetRequest(t, mux, http.MethodHead, resource)
	assert.Equal(t, http.StatusOK, head.Code)
	assert.Equal(t, "7", head.Header().Get("Content-Length"))
	assert.Equal(t, 0, head.Body.Len())
	assert.Equal(t, int32(0), downloads.Load())
	assert.Equal(t, http.StatusOK, nugetRequest(t, mux, http.MethodGet, resource).Code)
	_, ctx := logging.Configure(t.Context(), logging.Config{Level: slog.LevelError})
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, resource, nil)
	r.Header.Set("Range", "bytes=1-3")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	assert.Equal(t, http.StatusPartialContent, w.Code)
	assert.Equal(t, "ack", w.Body.String())
	assert.Equal(t, int32(1), downloads.Load())
}

func TestNuGetRegistrationDefaults(t *testing.T) {
	_, c := newNuGetTest(t, "https://api.nuget.org/v3/index.json")
	r := strategy.NewRegistry()
	strategy.RegisterNuGet(r, func() (*spool.Registry, error) { return newTestSpools(t), nil })
	s, err := r.Create(t.Context(), "nuget", &hcl.Block{Name: "nuget"}, c, http.NewServeMux(), map[string]string{
		"CACHEW_URL": "https://cache.example",
	})
	assert.NoError(t, err)
	assert.Equal(t, "nuget:api.nuget.org", s.String())
}

func TestNuGetPublicURLsShareOnlyArtifacts(t *testing.T) {
	var downloads atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".nupkg") {
			downloads.Add(1)
			_, _ = io.WriteString(w, "package")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"packageContent": "http://" + r.Host + "/package.nupkg"})
	}))
	defer upstream.Close()
	_, c := newNuGetTest(t, upstream.URL+"/index.json")
	for _, host := range []string{"one.example", "two.example"} {
		mux := http.NewServeMux()
		_, err := strategy.NewNuGet(t.Context(), strategy.NuGetConfig{
			Upstream: upstream.URL + "/index.json", PublicURL: "https://" + host + "//nuget/", MetadataTTL: time.Minute,
		}, c, mux, newTestSpools(t))
		assert.NoError(t, err)
		index := nugetRequest(t, mux, http.MethodGet, "https://attacker.example/nuget/index.json")
		assert.Equal(t, http.StatusOK, index.Code)
		var metadata map[string]string
		assert.NoError(t, json.Unmarshal(index.Body.Bytes(), &metadata))
		assert.Equal(t, strings.Replace(nugetResourceURL(upstream.URL+"/package.nupkg"), "cache.example", host, 1), metadata["packageContent"])
		assert.Equal(t, http.StatusOK, nugetRequest(t, mux, http.MethodGet, metadata["packageContent"]).Code)
	}
	assert.Equal(t, int32(1), downloads.Load())
}

func TestNuGetRejectsInvalidConfig(t *testing.T) {
	for name, change := range map[string]func(*strategy.NuGetConfig){
		"upstream scheme":      func(c *strategy.NuGetConfig) { c.Upstream = "file:///index.json" },
		"upstream credentials": func(c *strategy.NuGetConfig) { c.Upstream = "https://user:secret@example.com/index.json" },
		"upstream query":       func(c *strategy.NuGetConfig) { c.Upstream += "?token=secret" },
		"upstream traversal":   func(c *strategy.NuGetConfig) { c.Upstream = "https://example.com/%2e%2e/index.json" },
		"relative public URL":  func(c *strategy.NuGetConfig) { c.PublicURL = "/nuget" },
		"missing public URL":   func(c *strategy.NuGetConfig) { c.PublicURL = "" },
		"zero TTL":             func(c *strategy.NuGetConfig) { c.MetadataTTL = 0 },
		"negative TTL":         func(c *strategy.NuGetConfig) { c.MetadataTTL = -time.Second },
		"resource path":        func(c *strategy.NuGetConfig) { c.ResourceOrigins = []string{"https://cdn.example.com/path"} },
		"invalid resource":     func(c *strategy.NuGetConfig) { c.ResourceOrigins = []string{"%"} },
	} {
		t.Run(name, func(t *testing.T) {
			config := strategy.NuGetConfig{
				Upstream: "https://api.nuget.org/v3/index.json", PublicURL: "https://cache.example/nuget", MetadataTTL: time.Minute,
			}
			change(&config)
			_, err := strategy.NewNuGet(t.Context(), config, cache.NoOpCache(), http.NewServeMux(), newTestSpools(t))
			assert.Error(t, err)
		})
	}
}
