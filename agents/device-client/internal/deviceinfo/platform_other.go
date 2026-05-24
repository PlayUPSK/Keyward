//go:build !windows

package deviceinfo

import (
	"context"
	"runtime"
)

func collectPlatform(ctx context.Context, info *Info) {
	switch runtime.GOOS {
	case "darwin":
		collectDarwin(ctx, info)
	case "linux":
		collectLinux(ctx, info)
	}
}
