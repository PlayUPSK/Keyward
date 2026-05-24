package trayapp

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/browser"
	"github.com/playup/keyward/agents/device-client/internal/config"
	"github.com/playup/keyward/agents/device-client/internal/deviceinfo"
	"github.com/playup/keyward/agents/device-client/internal/devicekey"
	"github.com/playup/keyward/agents/device-client/internal/devicesync"
	"github.com/playup/keyward/agents/device-client/internal/enroll"
	"github.com/playup/keyward/agents/device-client/internal/localserver"
	"github.com/playup/keyward/agents/device-client/internal/state"
)

type App struct {
	Config    config.Config
	StatePath string
	LogPath   string
	State     state.State
}

func New(cfg config.Config, logPath string) (*App, error) {
	loaded, err := state.Load(state.DefaultPath())
	if err != nil {
		return nil, err
	}
	return &App{
		Config:    cfg,
		StatePath: state.DefaultPath(),
		LogPath:   logPath,
		State:     loaded,
	}, nil
}

func (a *App) IsEnrolled() bool {
	return a.Config.DeviceID != ""
}

func (a *App) LoginActionLabel() string {
	if a.IsEnrolled() {
		return "Open portal"
	}
	return "Login & enroll"
}

func (a *App) StatusLine() string {
	if a.Config.DeviceID == "" {
		return "Signed out / device not enrolled"
	}
	if a.State.LastSyncError != "" {
		return fmt.Sprintf("Sync error: %s", a.State.LastSyncError)
	}
	if a.State.UserEmail == "" {
		return fmt.Sprintf("Enrolled device %s, not synced yet", a.Config.DeviceID)
	}
	return fmt.Sprintf("%s: %s, %d servers, %d SSH identities, last sync %s", a.State.Company, a.State.UserEmail, a.State.ServerCount, a.State.IdentityCount, a.State.LastSyncAt.Format(time.RFC3339))
}

func (a *App) Sync(ctx context.Context) error {
	synced, err := devicesync.Sync(ctx, a.Config)
	if err != nil {
		a.State.LastSyncError = err.Error()
		_ = state.Save(a.StatePath, a.State)
		return err
	}
	a.State = synced
	a.State.LastSyncError = ""
	return state.Save(a.StatePath, a.State)
}

func (a *App) OpenPortal() error {
	return browser.Open(a.Config.PlatformURL + "/")
}

func (a *App) OpenLogin() error {
	return browser.Open(a.Config.PlatformURL + "/login")
}

func (a *App) OpenEnrollment() error {
	return browser.Open(a.Config.PlatformURL + "/devices/enroll")
}

func (a *App) OpenLog() error {
	return browser.Open(a.LogPath)
}

func (a *App) LoginOrEnroll(ctx context.Context) error {
	if a.IsEnrolled() {
		return a.OpenPortal()
	}

	result, err := enroll.Start(ctx, a.Config, enroll.StartRequest{
		DeviceName:  defaultDeviceName(),
		Platform:    runtime.GOOS,
		CallbackURL: a.Config.LocalCallbackURL,
	})
	if err != nil {
		return err
	}

	if result.Status == "awaiting_user" {
		callbackServer, err := localserver.Start(a.Config.LocalCallbackURL)
		if err != nil {
			return err
		}
		defer callbackServer.ShutdownSoon()

		approvalURL := a.Config.PlatformURL + result.CompleteURI
		if strings.HasPrefix(result.CompleteURI, "http://") || strings.HasPrefix(result.CompleteURI, "https://") {
			approvalURL = result.CompleteURI
		}
		if err := browser.Open(approvalURL); err != nil {
			return err
		}

		result, err = waitForApproval(ctx, a.Config, result, callbackServer)
		if err != nil {
			return err
		}
	}

	keyPair, err := devicekey.LoadOrCreate(a.Config.DeviceKeyPath)
	if err != nil {
		return err
	}
	publicKeyPEM, err := devicekey.PublicKeyPEM(keyPair.PublicKey)
	if err != nil {
		return err
	}

	finishResult, err := enroll.Finish(ctx, a.Config, enroll.FinishRequest{
		EnrollmentID:       result.EnrollmentID,
		PublicKey:          publicKeyPEM,
		Fingerprint:        devicekey.Fingerprint(keyPair.PublicKey),
		ChallengeSignature: devicekey.SignChallenge(keyPair.PrivateKey, result.Challenge),
		Posture:            deviceinfo.Collect(ctx),
	})
	if err != nil {
		return err
	}

	a.Config.DeviceID = finishResult.DeviceID
	if err := config.WriteDefault(a.Config); err != nil {
		return err
	}

	a.State = state.State{
		DeviceID:     finishResult.DeviceID,
		DeviceStatus: finishResult.Status,
	}
	if err := state.Save(a.StatePath, a.State); err != nil {
		return err
	}

	if err := a.Sync(ctx); err != nil {
		return fmt.Errorf("device enrolled but access sync failed: %w", err)
	}
	return nil
}

func waitForApproval(ctx context.Context, cfg config.Config, result enroll.StartResult, callbackServer *localserver.Server) (enroll.StartResult, error) {
	if callbackServer == nil {
		return enroll.PollApproved(ctx, cfg, result.EnrollmentID, result.Interval)
	}

	callbackCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	callbackCh := make(chan enrollResult, 1)
	go func() {
		callback, err := callbackServer.Wait(callbackCtx)
		if err != nil {
			callbackCh <- enrollResult{err: err}
			return
		}
		if callback.EnrollmentID != "" && callback.EnrollmentID != result.EnrollmentID {
			callbackCh <- enrollResult{err: fmt.Errorf("unexpected local callback for enrollment %s", callback.EnrollmentID)}
			return
		}
		if callback.Status != "" && callback.Status != "approved" {
			callbackCh <- enrollResult{err: fmt.Errorf("unexpected local callback status %s", callback.Status)}
			return
		}
		polled, err := enroll.PollOnce(callbackCtx, cfg, result.EnrollmentID)
		callbackCh <- enrollResult{result: polled, err: err}
	}()

	pollCh := make(chan enrollResult, 1)
	go func() {
		polled, err := enroll.PollApproved(callbackCtx, cfg, result.EnrollmentID, result.Interval)
		pollCh <- enrollResult{result: polled, err: err}
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

type enrollResult struct {
	result enroll.StartResult
	err    error
}

func defaultDeviceName() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "keyward-device"
	}
	return hostname
}

func (a *App) Logout() error {
	a.Config.DeviceID = ""
	a.State = state.State{}
	if err := config.WriteDefault(a.Config); err != nil {
		return err
	}
	return state.Save(a.StatePath, a.State)
}
