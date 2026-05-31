package jwtauth

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

type UserRevocationStore struct {
	client redis.UniversalClient
	prefix string
	ttl    time.Duration
}

func NewUserRevocationStore(client redis.UniversalClient) *UserRevocationStore {
	return &UserRevocationStore{
		client: client,
		prefix: "user_revoked_before:",
	}
}

func (s *UserRevocationStore) WithTTL(ttl time.Duration) *UserRevocationStore {
	s.ttl = ttl
	return s
}

func (s *UserRevocationStore) RevokeUserContext(ctx context.Context, userID int64, at time.Time) error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Set(ctx, s.key(userID), at.Unix(), s.ttl).Err()
}

func (s *UserRevocationStore) RevokedBeforeContext(ctx context.Context, userID int64) (int64, error) {
	if s == nil || s.client == nil {
		return 0, nil
	}
	val, err := s.client.Get(ctx, s.key(userID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil
		}
		return 0, err
	}

	return strconv.ParseInt(val, 10, 64)
}

func (s *UserRevocationStore) IsRevokedContext(ctx context.Context, userID int64, issuedAt int64) (bool, error) {
	revokedBefore, err := s.RevokedBeforeContext(ctx, userID)
	if err != nil {
		return false, err
	}
	if revokedBefore == 0 {
		return false, nil
	}

	return issuedAt <= revokedBefore, nil
}

func (s *UserRevocationStore) key(userID int64) string {
	return s.prefix + strconv.FormatInt(userID, 10)
}
