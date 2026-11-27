package cache_test

import (
	"context"

	"github.com/block/cachew/internal/cache"
	"github.com/block/cachew/internal/metadatadb"
)

func newTiered(ctx context.Context, caches ...cache.Cache) cache.Cache {
	return cache.MaybeNewTiered(ctx, caches, metadatadb.New(ctx, metadatadb.NewMemoryBackend()))
}
