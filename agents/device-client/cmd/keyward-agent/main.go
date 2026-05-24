package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/agent"
	"github.com/playup/keyward/agents/device-client/internal/certrequest"
	"github.com/playup/keyward/agents/device-client/internal/config"
	"github.com/playup/keyward/agents/device-client/internal/deviceinfo"
	"github.com/playup/keyward/agents/device-client/internal/devicekey"
	"github.com/playup/keyward/agents/device-client/internal/devicesync"
	"github.com/playup/keyward/agents/device-client/internal/enroll"
	"github.com/playup/keyward/agents/device-client/internal/localserver"
	"github.com/playup/keyward/agents/device-client/internal/state"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx := context.Background()
	switch os.Args[1] {
	case "configure":
		configureCmd(ctx, os.Args[2:])
	case "enroll":
		enrollCmd(ctx, os.Args[2:])
	case "issue-cert":
		issueCertCmd(ctx, os.Args[2:])
	case "serve":
		serveCmd(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func configureCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	platformURL := fs.String("platform-url", "", "platform base URL")
	callbackURL := fs.String("callback-url", "", "local browser callback URL")
	presenceMode := fs.String("presence-mode", "", "user presence mode: auto, windows_hello, macos_touchid, yubikey, command, none")
	presenceCommand := fs.String("presence-command", "", "custom user presence command for command/yubikey mode")
	presenceCache := fs.Int("presence-cache-seconds", 30, "seconds to cache a successful presence check")
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}
	if *platformURL != "" {
		cfg.PlatformURL = *platformURL
	}
	if *callbackURL != "" {
		cfg.LocalCallbackURL = *callbackURL
	}
	if *presenceMode != "" {
		cfg.UserPresenceMode = *presenceMode
	}
	if *presenceCommand != "" {
		cfg.UserPresenceCommand = *presenceCommand
	}
	cfg.UserPresenceCacheSeconds = *presenceCache

	if err := config.WriteDefault(cfg); err != nil {
		exitErr(err)
	}
	fmt.Printf("wrote config to %s\n", config.DefaultPath())
	_ = ctx
}

func enrollCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	deviceName := fs.String("name", "", "device display name")
	platform := fs.String("platform", "", "device platform")
	legacyUserEmail := fs.String("user-email", "", "legacy direct enrollment email")
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	startRequest := enroll.StartRequest{
		DeviceName:  *deviceName,
		Platform:    *platform,
		CallbackURL: cfg.LocalCallbackURL,
	}

	var result enroll.StartResult
	if *legacyUserEmail != "" {
		result, err = enroll.StartDirect(ctx, cfg, startRequest, *legacyUserEmail)
	} else {
		result, err = enroll.Start(ctx, cfg, startRequest)
	}
	if err != nil {
		exitErr(err)
	}

	if result.Status == "awaiting_user" {
		callbackServer, err := localserver.Start(cfg.LocalCallbackURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: local callback server disabled: %v\n", err)
		} else {
			defer callbackServer.ShutdownSoon()
		}

		approvalURL := cfg.PlatformURL + result.CompleteURI
		if strings.HasPrefix(result.CompleteURI, "http://") || strings.HasPrefix(result.CompleteURI, "https://") {
			approvalURL = result.CompleteURI
		}
		fmt.Printf("Open this URL to approve the device:\n%s\n\nCode: %s\nWaiting for approval...\n", approvalURL, result.UserCode)
		result, err = waitForApproval(ctx, cfg, result, callbackServer)
		if err != nil {
			exitErr(err)
		}
	}

	keyPair, err := devicekey.LoadOrCreate(cfg.DeviceKeyPath)
	if err != nil {
		exitErr(err)
	}
	publicKeyPEM, err := devicekey.PublicKeyPEM(keyPair.PublicKey)
	if err != nil {
		exitErr(err)
	}

	finishResult, err := enroll.Finish(ctx, cfg, enroll.FinishRequest{
		EnrollmentID:       result.EnrollmentID,
		PublicKey:          publicKeyPEM,
		Fingerprint:        devicekey.Fingerprint(keyPair.PublicKey),
		ChallengeSignature: devicekey.SignChallenge(keyPair.PrivateKey, result.Challenge),
		Posture:            deviceinfo.Collect(ctx),
	})
	if err != nil {
		exitErr(err)
	}

	cfg.DeviceID = finishResult.DeviceID
	if err := config.WriteDefault(cfg); err != nil {
		exitErr(err)
	}
	fmt.Printf("device enrolled: %s (%s)\n", finishResult.DeviceID, finishResult.TrustLevel)
}

func waitForApproval(ctx context.Context, cfg config.Config, result enroll.StartResult, callbackServer *localserver.Server) (enroll.StartResult, error) {
	if callbackServer == nil {
		return enroll.PollApproved(ctx, cfg, result.EnrollmentID, result.Interval)
	}

	callbackCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	callbackCh := make(chan errorResult, 1)
	go func() {
		callback, err := callbackServer.Wait(callbackCtx)
		if err != nil {
			callbackCh <- errorResult{err: err}
			return
		}
		if callback.EnrollmentID != "" && callback.EnrollmentID != result.EnrollmentID {
			callbackCh <- errorResult{err: fmt.Errorf("unexpected local callback for enrollment %s", callback.EnrollmentID)}
			return
		}
		if callback.Status != "" && callback.Status != "approved" {
			callbackCh <- errorResult{err: fmt.Errorf("unexpected local callback status %s", callback.Status)}
			return
		}
		polled, err := enroll.PollOnce(callbackCtx, cfg, result.EnrollmentID)
		if err != nil {
			callbackCh <- errorResult{err: err}
			return
		}
		callbackCh <- errorResult{result: polled}
	}()

	pollCh := make(chan errorResult, 1)
	go func() {
		polled, err := enroll.PollApproved(callbackCtx, cfg, result.EnrollmentID, result.Interval)
		pollCh <- errorResult{result: polled, err: err}
	}()

	select {
	case value := <-callbackCh:
		return value.result, value.err
	case value := <-pollCh:
		return value.result, value.err
	case <-callbackCtx.Done():
		return enroll.StartResult{}, callbackCtx.Err()
	}
}

type errorResult struct {
	result enroll.StartResult
	err    error
}

func issueCertCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("issue-cert", flag.ExitOnError)
	server := fs.String("server", "", "target server hostname or ID")
	principal := fs.String("principal", "", "target SSH principal")
	identityPath := fs.String("identity", "", "output SSH identity path")
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	keyPair, err := devicekey.LoadOrCreate(cfg.DeviceKeyPath)
	if err != nil {
		exitErr(err)
	}

	result, err := certrequest.Issue(ctx, cfg, keyPair.PrivateKey, certrequest.IssueOptions{
		Server:       *server,
		SSHPrincipal: *principal,
		IdentityPath: *identityPath,
	})
	if err != nil {
		exitErr(err)
	}

	outputPath := *identityPath
	if outputPath == "" {
		outputPath = cfg.DefaultIdentityPath()
	}
	fmt.Printf("issued cert serial %d valid until %s\nidentity: %s\ncertificate: %s-cert.pub\n", result.Serial, result.ValidBefore, outputPath, outputPath)
}

func serveCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socketPath := fs.String("socket", "", "SSH agent socket path")
	autoSync := fs.Bool("auto-sync", true, "automatically sync access and refresh SSH certificates")
	syncInterval := fs.Duration("sync-interval", time.Minute, "automatic access sync interval")
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	if *socketPath != "" {
		cfg.AgentSocketPath = *socketPath
	}

	if *autoSync {
		runAccessSync(ctx, cfg, "startup")
		if *syncInterval > 0 {
			go runAccessSyncLoop(ctx, cfg, *syncInterval)
		}
	}

	identityCount, err := agent.IssuedIdentityCount(cfg)
	if err != nil {
		exitErr(err)
	}

	fmt.Printf("serving SSH agent on %s\n", cfg.AgentSocketPath)
	fmt.Printf("loaded %d SSH identities\n", identityCount)
	if identityCount == 0 {
		fmt.Fprintln(os.Stderr, "warning: no issued Keyward SSH identities found; run issue-cert first")
	}

	if err := agent.Run(ctx, cfg); err != nil {
		exitErr(err)
	}
}

func runAccessSyncLoop(ctx context.Context, cfg config.Config, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runAccessSync(ctx, cfg, "background")
		}
	}
}

func runAccessSync(ctx context.Context, cfg config.Config, reason string) {
	if cfg.DeviceID == "" {
		fmt.Fprintf(os.Stderr, "warning: skipping %s access sync: device is not enrolled\n", reason)
		return
	}
	synced, err := devicesync.Sync(ctx, cfg)
	if err != nil {
		previous, _ := state.Load(state.DefaultPath())
		previous.LastSyncError = err.Error()
		_ = state.Save(state.DefaultPath(), previous)
		fmt.Fprintf(os.Stderr, "warning: %s access sync failed: %v\n", reason, err)
		return
	}
	synced.LastSyncError = ""
	_ = state.Save(state.DefaultPath(), synced)
	fmt.Fprintf(os.Stderr, "%s access sync complete: %d servers, %d SSH identities\n", reason, synced.ServerCount, synced.IdentityCount)
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: keyward-agent <configure|enroll|issue-cert|serve> [options]\n")
}

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
