package jwtauth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Blacklist struct {
	client redis.UniversalClient
	prefix string
}

func NewBlacklist(client redis.UniversalClient) *Blacklist {
	return &Blacklist{
		client: client,
		prefix: "blacklist:",
	}
}

func (b *Blacklist) WithPrefix(prefix string) *Blacklist {
	b.prefix = prefix
	return b
}

func (b *Blacklist) AddContext(ctx context.Context, token string, exp int64) error {
	if b == nil || b.client == nil {
		return nil
	}

	ttl := time.Until(time.Unix(exp, 0))
	if ttl <= 0 {
		return nil
	}

	key := b.prefix + HashToken(token)
	return b.client.Set(ctx, key, "1", ttl).Err()
}

func (b *Blacklist) ExistsContext(ctx context.Context, token string) (bool, error) {
	if b == nil || b.client == nil {
		return false, nil
	}

	key := b.prefix + HashToken(token)
	n, err := b.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return n > 0, nil
}
