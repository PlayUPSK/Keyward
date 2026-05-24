package agent

import (
	"context"

	"github.com/playup/keyward/agents/device-client/internal/config"
)

func Probe(cfg config.Config) error {
	return probePlatformServer(cfg)
}

func Reachable(cfg config.Config) bool {
	return reachablePlatformServer(cfg)
}

func Run(ctx context.Context, cfg config.Config) error {
	return runPlatformServer(ctx, cfg)
}
