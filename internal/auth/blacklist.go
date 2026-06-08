package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/samuelorobosa/hybridgate/internal/platform/redis"
)

const (
	blacklistJTIPrefix  = "blacklist:jti:"
	revokedUserPrefix   = "revoked:user:"
)

func blacklistKey(jti string) string {
	return blacklistJTIPrefix + jti
}

func revokedUserKey(userCUID string) string {
	return revokedUserPrefix + userCUID
}

func BlacklistJTI(ctx context.Context, jti string, ttl time.Duration) error {
	if err := redis.Client.Set(ctx, blacklistKey(jti), "1", ttl).Err(); err != nil {
		return fmt.Errorf("blacklist jti: %w", err)
	}
	return nil
}

func IsJTIBlacklisted(ctx context.Context, jti string) (bool, error) {
	n, err := redis.Client.Exists(ctx, blacklistKey(jti)).Result()
	if err != nil {
		return false, fmt.Errorf("check jti blacklist: %w", err)
	}
	return n > 0, nil
}

func MarkUserRevoked(ctx context.Context, userCUID string, ttl time.Duration) error {
	if err := redis.Client.Set(ctx, revokedUserKey(userCUID), "1", ttl).Err(); err != nil {
		return fmt.Errorf("mark user revoked: %w", err)
	}
	return nil
}

func IsUserRevoked(ctx context.Context, userCUID string) (bool, error) {
	n, err := redis.Client.Exists(ctx, revokedUserKey(userCUID)).Result()
	if err != nil {
		return false, fmt.Errorf("check user revoked: %w", err)
	}
	return n > 0, nil
}
