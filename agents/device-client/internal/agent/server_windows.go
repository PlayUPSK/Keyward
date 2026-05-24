//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/ndbeals/winssh-pageant/pageant"
	"github.com/playup/keyward/agents/device-client/internal/config"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func reachablePlatformServer(cfg config.Config) bool {
	timeout := 50 * time.Millisecond
	log.Printf("agent/windows: reachability dial start for %s with timeout %s", cfg.AgentSocketPath, timeout)
	conn, err := winio.DialPipe(cfg.AgentSocketPath, &timeout)
	if err != nil {
		log.Printf("agent/windows: reachability dial failed for %s: %v", cfg.AgentSocketPath, err)
		return false
	}
	_ = conn.Close()
	log.Printf("agent/windows: reachability dial succeeded for %s", cfg.AgentSocketPath)
	return true
}

func probePlatformServer(cfg config.Config) error {
	log.Printf("agent/windows: probe listen start for %s", cfg.AgentSocketPath)
	listener, err := winio.ListenPipe(cfg.AgentSocketPath, nil)
	if err != nil {
		log.Printf("agent/windows: probe listen failed for %s: %v", cfg.AgentSocketPath, err)
		return fmt.Errorf("listen on %s: %w", cfg.AgentSocketPath, err)
	}
	log.Printf("agent/windows: probe listen succeeded for %s", cfg.AgentSocketPath)
	_ = listener.Close()
	log.Printf("agent/windows: probe listener closed for %s", cfg.AgentSocketPath)
	return nil
}

func runPlatformServer(ctx context.Context, cfg config.Config) error {
	log.Printf("agent/windows: server listen start for %s", cfg.AgentSocketPath)
	listener, err := winio.ListenPipe(cfg.AgentSocketPath, nil)
	if err != nil {
		log.Printf("agent/windows: server listen failed for %s: %v", cfg.AgentSocketPath, err)
		return fmt.Errorf("listen on %s: %w", cfg.AgentSocketPath, err)
	}
	log.Printf("agent/windows: server listen ready for %s", cfg.AgentSocketPath)

	go func() {
		<-ctx.Done()
		log.Printf("agent/windows: context canceled, closing listener for %s", cfg.AgentSocketPath)
		_ = listener.Close()
	}()

	go func() {
		log.Printf("agent/windows: accept loop started for %s", cfg.AgentSocketPath)
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					log.Printf("agent/windows: accept loop stopped for %s", cfg.AgentSocketPath)
					return
				}
				log.Printf("agent/windows: accept failed for %s: %v", cfg.AgentSocketPath, err)
				fmt.Fprintf(os.Stderr, "warning: ssh-agent pipe accept failed: %v\n", err)
				return
			}
			log.Printf("agent/windows: accepted agent connection on %s", cfg.AgentSocketPath)

			go func() {
				defer conn.Close()
				log.Printf("agent/windows: serving agent connection on %s", cfg.AgentSocketPath)
				if err := sshagent.ServeAgent(newDynamicAgent(cfg), conn); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
					log.Printf("agent/windows: request handler failed on %s: %v", cfg.AgentSocketPath, err)
					fmt.Fprintf(os.Stderr, "warning: ssh-agent pipe request failed: %v\n", err)
					return
				}
				log.Printf("agent/windows: agent connection finished on %s", cfg.AgentSocketPath)
			}()
		}
	}()

	go func() {
		log.Printf("agent/windows: starting Pageant bridge goroutine for %s", cfg.AgentSocketPath)
		bridge := pageant.New(cfg.AgentSocketPath, true, func(_ *pageant.Pageant, request []byte) ([]byte, error) {
			log.Printf("agent/windows: Pageant request received on %s (%d bytes)", cfg.AgentSocketPath, len(request))
			return serveRawRequest(cfg, request)
		})
		bridge.Run()
		log.Printf("agent/windows: Pageant bridge exited for %s", cfg.AgentSocketPath)
	}()

	log.Printf("agent/windows: server fully initialized for %s", cfg.AgentSocketPath)
	<-ctx.Done()
	log.Printf("agent/windows: runPlatformServer returning for %s", cfg.AgentSocketPath)
	return nil
}