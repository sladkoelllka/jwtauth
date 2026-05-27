package jwtauth

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type RefreshStore struct {
	client *redis.Client
	prefix string
}

func NewRefreshStore(client *redis.Client) *RefreshStore {
	return &RefreshStore{
		client: client,
		prefix: "refresh:",
	}
}

func (s *RefreshStore) Save(jti string, userID int64, exp int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ttl := time.Until(time.Unix(exp, 0))
	return s.client.Set(ctx, s.prefix+jti, userID, ttl).Err()
}

// Use = проверить + удалить (rotation)
func (s *RefreshStore) Use(jti string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	key := s.prefix + jti

	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	_ = s.client.Del(ctx, key).Err()

	id, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, err
	}

	return id, nil
}
