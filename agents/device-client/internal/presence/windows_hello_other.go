//go:build !windows

package presence

import (
	"context"
	"fmt"

	"github.com/playup/keyward/agents/device-client/internal/config"
)

func runWindowsHello(ctx context.Context, cfg config.Config, reason string) error {
	return fmt.Errorf("windows_hello mode is only supported on Windows")
}
