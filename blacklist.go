package jwtauth

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type Blacklist struct {
	client *redis.Client
	prefix string
}

func NewBlacklist(client *redis.Client) *Blacklist {
	return &Blacklist{
		client: client,
		prefix: "blacklist:",
	}
}

func (b *Blacklist) Add(token string, exp int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ttl := time.Until(time.Unix(exp, 0))
	if ttl <= 0 {
		return nil
	}

	key := b.prefix + HashToken(token)
	return b.client.Set(ctx, key, "1", ttl).Err()
}

func (b *Blacklist) Exists(token string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	key := b.prefix + HashToken(token)
	n, err := b.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return n > 0, nil
}