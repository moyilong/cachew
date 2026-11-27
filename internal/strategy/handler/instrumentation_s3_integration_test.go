//go:build integration

package handler_test

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/metadatadb"
	"github.com/block/cachew/internal/s3client"
	"github.com/block/cachew/internal/s3client/s3clienttest"
	"github.com/block/cachew/internal/strategy/handler"
)

func TestArtifactS3(t *testing.T) {
	reader := artifactReader(t)
	bucket := s3clienttest.Start(t)
	provider := s3client.NewClientProvider(artifactContext(t), s3client.Config{Endpoint: s3clienttest.Addr, UseSSL: false})
	shared, err := cache.NewS3(artifactContext(t), cache.S3Config{Bucket: bucket, MaxTTL: time.Hour, UploadPartSizeMB: 16}, provider)
	assert.NoError(t, err)
	disk, err := cache.NewDisk(artifactContext(t), cache.DiskConfig{Root: t.TempDir()})
	assert.NoError(t, err)
	key := cache.NewKey("/artifact")
	assert.NoError(t, cache.WriteFunc(artifactContext(t), shared, key, nil, time.Hour, func(w io.Writer) error { _, err := io.WriteString(w, "artifact"); return err }))
	c := cache.MaybeNewTiered(artifactContext(t), []cache.Cache{disk, shared}, metadatadb.New(artifactContext(t), metadatadb.NewMemoryBackend()))
	defer c.Close()
	h := handler.New(http.DefaultClient, c, newTestSpools(t)).Metrics("host", "registry.example")
	w, labels := serveLabeled(h, artifactHTTPRequest(t, "/artifact"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "artifact", w.Body.String())
	assert.Equal(t, "s3", labels[handler.CacheSourceAttribute])
	assert.Equal(t, int64(1), artifactCount(t, reader, "cachew.cache.fills", "purpose", "backfill", "result", "success"))
	assert.Equal(t, int64(0), artifactCount(t, reader, "cachew.origin.requests"))
}
