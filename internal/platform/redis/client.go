package redis

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

var Client *goredis.Client

func Init() {
	redisURL := strings.TrimSpace(os.Getenv("REDIS_URL"))
	if redisURL == "" {
		log.Panic("redis: REDIS_URL is empty")
	}

	client, err := Open(redisURL)
	if err != nil {
		log.Panicf("failed to open redis: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.Panicf("failed to ping redis: %v", err)
	}

	Client = client
	log.Println("redis connected successfully")
}

func Open(redisURL string) (*goredis.Client, error) {
	redisURL = strings.TrimSpace(redisURL)
	if redisURL == "" {
		return nil, fmt.Errorf("redis: URL is empty")
	}

	opt, err := goredis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis: parse URL: %w", err)
	}

	return goredis.NewClient(opt), nil
}
