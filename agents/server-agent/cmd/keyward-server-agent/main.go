package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/playup/keyward/agents/server-agent/internal/config"
	"github.com/playup/keyward/agents/server-agent/internal/enroll"
	"github.com/playup/keyward/agents/server-agent/internal/openssh"
	agentsync "github.com/playup/keyward/agents/server-agent/internal/sync"
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
	case "create-token":
		createTokenCmd(ctx, os.Args[2:])
	case "enroll":
		enrollCmd(ctx, os.Args[2:])
	case "render-sshd-config":
		renderSSHDConfigCmd(ctx, os.Args[2:])
	case "sync":
		syncCmd(ctx, os.Args[2:])
	case "watch":
		watchCmd(ctx, os.Args[2:])
	case "verify-revocation":
		verifyRevocationCmd(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func configureCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	platformURL := fs.String("platform-url", "https://localhost:8443", "platform base URL")
	stateDir := fs.String("state-dir", "", "agent state directory")
	trustedUserCAPath := fs.String("trusted-user-ca", "", "trusted user CA output path")
	sshdIncludePath := fs.String("sshd-include", "", "OpenSSH include config path")
	revocationPath := fs.String("revocation-state", "", "revocation state output path")
	revokedKeysPath := fs.String("revoked-keys", "", "OpenSSH KRL path for RevokedKeys")
	_ = fs.Parse(args)

	cfg := config.Default()
	cfg.PlatformURL = *platformURL
	if *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	if *trustedUserCAPath != "" {
		cfg.TrustedUserCAPath = *trustedUserCAPath
	}
	if *sshdIncludePath != "" {
		cfg.SSHDIncludePath = *sshdIncludePath
	}
	if *revocationPath != "" {
		cfg.RevocationPath = *revocationPath
	}
	if *revokedKeysPath != "" {
		cfg.RevokedKeysPath = *revokedKeysPath
	}
	if err := config.WriteDefault(cfg); err != nil {
		exitErr(err)
	}
	fmt.Printf("wrote config to %s\n", config.DefaultPath())
	_ = ctx
}

func createTokenCmd(ctx context.Context, args []string) {
	_ = ctx
	_ = args
	exitErr(fmt.Errorf("server enrollment tokens must be created by an admin in the Keyward web UI"))
}

func enrollCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "server enrollment token")
	tokenFile := fs.String("token-file", "", "path to a file containing the server enrollment token")
	hostname := fs.String("hostname", "", "hostname to register; defaults to the operating system hostname")
	publicKey := fs.String("public-key", "", "server public key or path to a .pub file")
	agentVersion := fs.String("agent-version", "dev", "agent version")
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	resolvedToken := strings.TrimSpace(*token)
	if resolvedToken == "" && strings.TrimSpace(*tokenFile) != "" {
		data, err := os.ReadFile(strings.TrimSpace(*tokenFile))
		if err != nil {
			exitErr(fmt.Errorf("read token file: %w", err))
		}
		resolvedToken = strings.TrimSpace(string(data))
	}
	if resolvedToken == "" {
		exitErr(fmt.Errorf("--token or --token-file is required"))
	}

	resolvedHostname := strings.TrimSpace(*hostname)
	if resolvedHostname == "" {
		osHostname, err := os.Hostname()
		if err != nil {
			exitErr(fmt.Errorf("resolve hostname: %w", err))
		}
		resolvedHostname = strings.TrimSpace(osHostname)
	}
	if resolvedHostname == "" {
		exitErr(fmt.Errorf("--hostname is required because the operating system hostname is empty"))
	}

	resolvedPublicKey, err := resolvePublicKey(*publicKey)
	if err != nil {
		exitErr(err)
	}

	result, err := enroll.RedeemToken(ctx, cfg, enroll.RedeemTokenRequest{
		Token:        resolvedToken,
		PublicKey:    resolvedPublicKey,
		AgentVersion: *agentVersion,
		Hostname:     resolvedHostname,
	})
	if err != nil {
		exitErr(err)
	}
	fmt.Printf("server enrolled: %s (%s)\n", result.ServerID, result.Hostname)
	cfg.ServerID = result.ServerID
	if err := config.WriteDefault(cfg); err != nil {
		exitErr(err)
	}
}

func renderSSHDConfigCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("render-sshd-config", flag.ExitOnError)
	trustedCAPath := fs.String("trusted-user-ca", "/etc/ssh/keyward/trusted_user_ca.pub", "trusted user CA path")
	revokedKeysPath := fs.String("revoked-keys", "/etc/ssh/keyward/revoked.krl", "OpenSSH KRL path for RevokedKeys")
	_ = fs.Parse(args)

	fmt.Print(openssh.RenderTrustedUserCAAndRevocationConfig(*trustedCAPath, *revokedKeysPath))
	_ = ctx
}

func syncCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	if err := agentsync.Run(ctx, cfg); err != nil {
		exitErr(err)
	}
}

func watchCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Duration("interval", 2*time.Second, "platform sync interval")
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	if err := agentsync.Watch(ctx, cfg, *interval); err != nil {
		exitErr(err)
	}
}

func verifyRevocationCmd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("verify-revocation", flag.ExitOnError)
	certPath := fs.String("cert", "", "SSH user certificate path to check, usually id_ed25519-cert.pub")
	_ = fs.Parse(args)

	cfg, err := config.LoadDefault()
	if err != nil {
		exitErr(err)
	}

	fmt.Printf("trusted CA: %s\n", cfg.TrustedUserCAPath)
	fmt.Printf("revoked keys: %s\n", cfg.RevokedKeysPath)
	fmt.Printf("sshd include: %s\n\n", cfg.SSHDIncludePath)

	if include, err := os.ReadFile(cfg.SSHDIncludePath); err == nil {
		fmt.Printf("sshd include contents:\n%s\n", string(include))
	} else {
		fmt.Printf("warning: cannot read sshd include: %v\n\n", err)
	}
	printEffectiveSSHDRevocationConfig(ctx)

	if _, err := os.Stat(cfg.RevokedKeysPath); err != nil {
		exitErr(fmt.Errorf("revoked keys KRL is not readable: %w", err))
	}

	fmt.Println("KRL contents:")
	if output, err := exec.CommandContext(ctx, "ssh-keygen", "-Q", "-l", "-f", cfg.RevokedKeysPath).CombinedOutput(); err != nil {
		exitErr(fmt.Errorf("list KRL failed: %w: %s", err, strings.TrimSpace(string(output))))
	} else {
		fmt.Print(string(output))
	}

	if strings.TrimSpace(*certPath) == "" {
		fmt.Println("\nno --cert provided; pass --cert /path/to/id_ed25519-cert.pub to check a specific login certificate")
		return
	}

	fmt.Printf("\ncertificate details for %s:\n", *certPath)
	if output, err := exec.CommandContext(ctx, "ssh-keygen", "-L", "-f", *certPath).CombinedOutput(); err != nil {
		exitErr(fmt.Errorf("read certificate failed: %w: %s", err, strings.TrimSpace(string(output))))
	} else {
		fmt.Print(string(output))
	}

	output, err := exec.CommandContext(ctx, "ssh-keygen", "-Q", "-f", cfg.RevokedKeysPath, *certPath).CombinedOutput()
	if err == nil {
		exitErr(fmt.Errorf("certificate is NOT revoked by %s", cfg.RevokedKeysPath))
	}
	fmt.Printf("\nrevocation check result:\n%s", string(output))
	fmt.Println("certificate is revoked by the KRL")
}

func printEffectiveSSHDRevocationConfig(ctx context.Context) {
	output, err := exec.CommandContext(ctx, "sshd", "-T").CombinedOutput()
	if err != nil {
		fmt.Printf("warning: cannot inspect effective sshd config with sshd -T: %v: %s\n\n", err, strings.TrimSpace(string(output)))
		return
	}

	fmt.Println("effective sshd config:")
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "trustedusercakeys ") ||
			strings.HasPrefix(line, "revokedkeys ") ||
			strings.HasPrefix(line, "pubkeyauthentication ") ||
			strings.HasPrefix(line, "authorizedkeysfile ") {
			fmt.Println(line)
		}
	}
	fmt.Println()
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: keyward-server-agent <configure|create-token|enroll|render-sshd-config|sync|watch|verify-revocation> [options]\n")
}

func resolvePublicKey(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed != "" {
		if looksLikePublicKey(trimmed) {
			return trimmed, nil
		}
		return readPublicKeyFile(trimmed)
	}

	defaultPath := "/etc/ssh/ssh_host_ed25519_key.pub"
	if _, err := os.Stat(defaultPath); err == nil {
		return readPublicKeyFile(defaultPath)
	}

	return "", fmt.Errorf("--public-key is required, or place the host key at %s", defaultPath)
}

func looksLikePublicKey(value string) bool {
	return strings.HasPrefix(value, "ssh-")
}

func readPublicKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read public key %s: %w", path, err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("public key file %s is empty", path)
	}
	if !looksLikePublicKey(key) {
		return "", fmt.Errorf("public key file %s does not contain an SSH public key", filepath.Clean(path))
	}
	return key, nil
}

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
