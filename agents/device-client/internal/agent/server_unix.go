//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/playup/keyward/agents/device-client/internal/config"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func reachablePlatformServer(cfg config.Config) bool {
	conn, err := net.Dial("unix", cfg.AgentSocketPath)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probePlatformServer(cfg config.Config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.AgentSocketPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(cfg.AgentSocketPath)

	listener, err := net.Listen("unix", cfg.AgentSocketPath)
	if err != nil {
		return err
	}
	_ = listener.Close()
	_ = os.Remove(cfg.AgentSocketPath)
	return nil
}

func runPlatformServer(ctx context.Context, cfg config.Config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.AgentSocketPath), 0o700); err != nil {
		return err
	}
	_ = os.Remove(cfg.AgentSocketPath)

	listener, err := net.Listen("unix", cfg.AgentSocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(cfg.AgentSocketPath)
	}()

	if err := os.Chmod(cfg.AgentSocketPath, 0o600); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		go func() {
			defer conn.Close()
			if err := sshagent.ServeAgent(newDynamicAgent(cfg), conn); err != nil && !errors.Is(err, net.ErrClosed) {
				fmt.Fprintf(os.Stderr, "warning: ssh-agent request failed: %v\n", err)
			}
		}()
	}
}