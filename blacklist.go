package jwtauth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Blacklist struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

var bgCtx = context.Background()

func NewBlacklist(client *redis.Client, ttl time.Duration) *Blacklist {
	return &Blacklist{client: client, prefix: "blacklist:", ttl: ttl}
}

func (b *Blacklist) Add(token string) error {
	key := b.prefix + HashToken(token)
	return b.client.Set(bgCtx, key, "1", b.ttl).Err()
}

func (b *Blacklist) Exists(token string) (bool, error) {
	key := b.prefix + HashToken(token)
	n, err := b.client.Exists(bgCtx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (b *Blacklist) Remove(token string) error {
	key := b.prefix + HashToken(token)
	return b.client.Del(bgCtx, key).Err()
}
