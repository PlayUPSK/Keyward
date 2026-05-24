package presence

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/config"
	"github.com/playup/keyward/agents/device-client/internal/process"
)

var cache = struct {
	sync.Mutex
	until time.Time
}{}

func Verify(ctx context.Context, cfg config.Config, reason string) error {
	cacheSeconds := cfg.UserPresenceCacheSeconds
	if cacheSeconds <= 0 {
		cacheSeconds = 30
	}

	cache.Lock()
	if time.Now().Before(cache.until) {
		cache.Unlock()
		return nil
	}
	cache.Unlock()

	if err := verifyUncached(ctx, cfg, reason); err != nil {
		return err
	}

	cache.Lock()
	cache.until = time.Now().Add(time.Duration(cacheSeconds) * time.Second)
	cache.Unlock()
	return nil
}

func verifyUncached(ctx context.Context, cfg config.Config, reason string) error {
	mode := strings.TrimSpace(cfg.UserPresenceMode)
	if mode == "" {
		mode = "auto"
	}

	switch mode {
	case "none", "disabled":
		return nil
	case "auto":
		switch runtime.GOOS {
		case "windows":
			return runWindowsHello(ctx, cfg, reason)
		case "darwin":
			return runMacOSTouchID(ctx, reason)
		default:
			return fmt.Errorf("user presence required but no native verifier is configured; set user_presence_mode=command")
		}
	case "windows_hello":
		return runWindowsHello(ctx, cfg, reason)
	case "macos_touchid":
		return runMacOSTouchID(ctx, reason)
	case "yubikey", "command":
		if strings.TrimSpace(cfg.UserPresenceCommand) == "" {
			return fmt.Errorf("%s presence mode requires user_presence_command", mode)
		}
		return runShellCommand(ctx, cfg.UserPresenceCommand, reason)
	default:
		return fmt.Errorf("unknown user presence mode %q", mode)
	}
}

func runMacOSTouchID(ctx context.Context, reason string) error {
	script := fmt.Sprintf(`display dialog %q with title "Keyward" buttons {"Cancel", "Approve"} default button "Approve" cancel button "Cancel"`, reason)
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	process.HideWindow(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("macOS user presence verification failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runShellCommand(ctx context.Context, command string, reason string) error {
	cmd := exec.CommandContext(ctx, shellName(), shellArg(), command)
	cmd.Env = append(cmd.Environ(), "KEYWARD_SSH_REASON="+reason, "PASSKEY_SSH_REASON="+reason)
	process.HideWindow(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("user presence command failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func shellName() string {
	if runtime.GOOS == "windows" {
		return "cmd.exe"
	}
	return "/bin/sh"
}

func shellArg() string {
	if runtime.GOOS == "windows" {
		return "/C"
	}
	return "-c"
}
