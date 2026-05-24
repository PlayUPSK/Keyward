package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/agent"
	"github.com/playup/keyward/agents/device-client/internal/clientlog"
	"github.com/playup/keyward/agents/device-client/internal/config"
	"github.com/playup/keyward/agents/device-client/internal/opensshcfg"
	"github.com/playup/keyward/agents/device-client/internal/tray"
	"github.com/playup/keyward/agents/device-client/internal/trayapp"
)

const windowsFallbackAgentPipe = `\\.\pipe\keyward-agent`

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	logPath, logFile, err := clientlog.Setup("keyward-tray")
	if err != nil {
		exitErr(err)
	}
	defer logFile.Close()
	log.Printf("starting Keyward tray app")

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	app, err := trayapp.New(cfg, logPath)
	if err != nil {
		exitErr(err)
	}

	if app.IsEnrolled() {
		log.Print("running startup access sync")
		if err := app.Sync(ctx); err != nil {
			log.Printf("startup access sync failed: %v", err)
		} else {
			log.Printf("startup access sync complete: %d servers, %d SSH identities", app.State.ServerCount, app.State.IdentityCount)
		}
	} else {
		log.Print("skipping startup access sync: device is not enrolled")
	}
	startBackgroundAccessSync(ctx, app, time.Minute)

	identityCount, err := agent.IssuedIdentityCount(cfg)
	if err != nil {
		exitErr(err)
	}
	log.Printf("loaded %d SSH identities", identityCount)
	if identityCount == 0 {
		log.Print("no Keyward SSH identities are available yet")
	}
	cfg = startTrayAgent(ctx, cfg)

	if err := tray.Run(ctx, app); err != nil {
		exitErr(err)
	}
	log.Print("tray app stopped")
}

func startBackgroundAccessSync(ctx context.Context, app *trayapp.App, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !app.IsEnrolled() {
					continue
				}
				if err := app.Sync(ctx); err != nil {
					log.Printf("background access sync failed: %v", err)
					continue
				}
				log.Printf("background access sync complete: %d servers, %d SSH identities", app.State.ServerCount, app.State.IdentityCount)
			}
		}
	}()
}

func startTrayAgent(ctx context.Context, cfg config.Config) config.Config {
	log.Printf("starting SSH agent on %s", cfg.AgentSocketPath)
	if err := agent.Probe(cfg); err != nil {
		if runtime.GOOS == "windows" && isWindowsPipeAccessDenied(err) {
			log.Printf("default Windows OpenSSH pipe unavailable: %v", err)
			fallback := cfg
			fallback.AgentSocketPath = windowsFallbackAgentPipe
			cfg = fallback
			log.Printf("falling back to %s", cfg.AgentSocketPath)
			log.Printf("configure Windows OpenSSH with IdentityAgent %s", opensshcfg.ConfiguredPipe(cfg))
		} else {
			log.Printf("ssh agent startup probe failed: %v", err)
			return cfg
		}
	} else {
		log.Printf("startup probe succeeded on %s", cfg.AgentSocketPath)
	}

	if runtime.GOOS == "windows" {
		if err := opensshcfg.EnsureIdentityAgentConfig(cfg.AgentSocketPath); err != nil {
			log.Printf("failed to configure Windows OpenSSH include for %s: %v", cfg.AgentSocketPath, err)
		} else {
			log.Printf("configured Windows OpenSSH include %s for IdentityAgent %s", opensshcfg.ConfigPath(), opensshcfg.ConfiguredPipe(cfg))
		}
	}

	launchTrayAgent(ctx, cfg)
	return cfg
}

func launchTrayAgent(ctx context.Context, cfg config.Config) {
	launchTrayAgentInProcess(ctx, cfg)

	log.Printf("starting background reachability watch for %s", cfg.AgentSocketPath)
	go func(active config.Config) {
		if waitForReachableAgent(ctx, active, 3*time.Second) {
			log.Printf("ssh agent reachable on %s", active.AgentSocketPath)
			return
		}

		log.Printf("ssh agent did not become reachable on %s after startup", active.AgentSocketPath)
		retryStartTrayAgent(ctx, active)
	}(cfg)
}

func launchTrayAgentInProcess(ctx context.Context, cfg config.Config) {
	log.Printf("launching tray agent goroutine for %s", cfg.AgentSocketPath)
	go func(active config.Config) {
		log.Printf("agent goroutine entered for %s", active.AgentSocketPath)
		if err := agent.Run(ctx, active); err != nil {
			log.Printf("ssh agent stopped with error: %v", err)
			return
		}
		log.Printf("agent goroutine exited cleanly for %s", active.AgentSocketPath)
	}(cfg)
}

func waitForReachableAgent(ctx context.Context, cfg config.Config, timeout time.Duration) bool {
	log.Printf("waitForReachableAgent start for %s with timeout %s", cfg.AgentSocketPath, timeout)
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	attempt := 0

	for {
		attempt++
		if agent.Reachable(cfg) {
			log.Printf("waitForReachableAgent success for %s on attempt %d", cfg.AgentSocketPath, attempt)
			return true
		}

		select {
		case <-ctx.Done():
			log.Printf("waitForReachableAgent canceled for %s on attempt %d", cfg.AgentSocketPath, attempt)
			return false
		case <-deadline.C:
			result := agent.Reachable(cfg)
			log.Printf("waitForReachableAgent deadline reached for %s on attempt %d, final reachable=%t", cfg.AgentSocketPath, attempt, result)
			return result
		case <-ticker.C:
			if attempt == 1 || attempt%5 == 0 {
				log.Printf("waitForReachableAgent still waiting for %s after %d attempts", cfg.AgentSocketPath, attempt)
			}
		}
	}
}

func retryStartTrayAgent(ctx context.Context, cfg config.Config) {
	log.Printf("retryStartTrayAgent scheduled for %s", cfg.AgentSocketPath)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	attempt := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("retryStartTrayAgent canceled for %s", cfg.AgentSocketPath)
			return
		case <-ticker.C:
			attempt++
			log.Printf("retryStartTrayAgent tick %d for %s", attempt, cfg.AgentSocketPath)
			if agent.Reachable(cfg) {
				log.Printf("Keyward agent became reachable on %s", cfg.AgentSocketPath)
				return
			}
			if err := agent.Probe(cfg); err != nil {
				if isWindowsPipeAccessDenied(err) {
					continue
				}
				log.Printf("retry probe failed on %s: %v", cfg.AgentSocketPath, err)
				continue
			}
			log.Printf("retrying SSH agent startup on %s", cfg.AgentSocketPath)
			launchTrayAgent(ctx, cfg)
			return
		}
	}
}

func isWindowsPipeAccessDenied(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "access is denied")
}

func exitErr(err error) {
	log.Printf("fatal error: %v", err)
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
