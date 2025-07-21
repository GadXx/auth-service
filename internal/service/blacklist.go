package service

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type BlacklistService struct {
	Cache *redis.Client
}

func NewBlacklistService(redis *redis.Client) *BlacklistService {
	return &BlacklistService{
		Cache: redis,
	}
}

func (s *BlacklistService) AddToken(sid string, ttl time.Duration) error {
	key := "bl:" + sid
	err := s.Cache.Set(context.Background(), key, "blacklist", ttl).Err()
	return err
}

func (s *BlacklistService) IsTokenBlacklist(sid string) (bool, error) {
	key := "bl:" + sid
	res, err := s.Cache.Exists(context.Background(), key).Result()
	return res == 1, err
}
