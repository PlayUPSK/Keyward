//go:build windows

package tray

import (
	"bytes"
	"context"
	_ "embed"
	"image/png"
	"log"
	"strings"

	"github.com/lxn/walk"

	"github.com/playup/keyward/agents/device-client/internal/trayapp"
)

const appName = "Keyward Client"

//go:embed keyward-logo-no-text-transparent.png
var keywardTrayIconPNG []byte

func Run(ctx context.Context, app *trayapp.App) error {
	walk.App().SetProductName(appName)

	mw, err := walk.NewMainWindow()
	if err != nil {
		return err
	}
	defer mw.Dispose()
	mw.SetTitle(appName)
	mw.SetVisible(false)

	ni, err := walk.NewNotifyIcon(mw)
	if err != nil {
		return err
	}
	defer ni.Dispose()

	icon, err := keywardIcon()
	if err != nil {
		log.Printf("failed to load Keyward tray icon, using fallback: %v", err)
		icon = walk.IconShield()
	}
	if err := ni.SetIcon(icon); err != nil {
		return err
	}
	if err := ni.SetToolTip(appName); err != nil {
		return err
	}

	statusAction, err := newTrayAction(app.StatusLine(), false, nil)
	if err != nil {
		return err
	}
	syncAction, err := newTrayAction("Sync access", true, nil)
	if err != nil {
		return err
	}
	loginAction, err := newTrayAction(app.LoginActionLabel(), true, nil)
	if err != nil {
		return err
	}
	logoutAction, err := newTrayAction("Logout local device", true, nil)
	if err != nil {
		return err
	}
	logAction, err := newTrayAction("Open log file", true, nil)
	if err != nil {
		return err
	}
	quitAction, err := newTrayAction("Quit", true, nil)
	if err != nil {
		return err
	}

	actions := ni.ContextMenu().Actions()
	for _, action := range []*walk.Action{statusAction, walk.NewSeparatorAction(), syncAction, loginAction, logoutAction, logAction, walk.NewSeparatorAction(), quitAction} {
		if err := actions.Add(action); err != nil {
			return err
		}
	}

	refreshStatus := func() {
		_ = statusAction.SetText(escapeMenuText(app.StatusLine()))
		_ = loginAction.SetText(escapeMenuText(app.LoginActionLabel()))
	}
	setBusy := func(busy bool) {
		_ = syncAction.SetEnabled(!busy)
		_ = loginAction.SetEnabled(!busy)
		_ = logoutAction.SetEnabled(!busy)
		if busy {
			_ = statusAction.SetText("Syncing access...")
			return
		}
		refreshStatus()
	}
	showError := func(title string, err error) {
		log.Printf("%s: %v", title, err)
		_ = ni.ShowError(title, err.Error())
	}
	showInfo := func(message string) {
		log.Print(message)
		_ = ni.ShowInfo(appName, message)
	}

	syncAction.Triggered().Attach(func() {
		setBusy(true)
		go func() {
			err := app.Sync(ctx)
			mw.Synchronize(func() {
				setBusy(false)
				if err != nil {
					showError("Sync failed", err)
					return
				}
				showInfo("Access sync complete")
			})
		}()
	})

	loginAction.Triggered().Attach(func() {
		wasEnrolled := app.IsEnrolled()
		setBusy(true)
		go func() {
			err := app.LoginOrEnroll(ctx)
			mw.Synchronize(func() {
				setBusy(false)
				if err != nil {
					showError("Login failed", err)
					return
				}
				if !wasEnrolled {
					showInfo("Device enrolled and synced")
				}
			})
		}()
	})

	logoutAction.Triggered().Attach(func() {
		if err := app.Logout(); err != nil {
			showError("Logout failed", err)
			return
		}
		refreshStatus()
		showInfo("Local device state cleared")
	})

	logAction.Triggered().Attach(func() {
		if err := app.OpenLog(); err != nil {
			showError("Open log failed", err)
			return
		}
		log.Printf("opened log file: %s", app.LogPath)
	})

	quitAction.Triggered().Attach(func() {
		log.Print("quitting tray app")
		_ = mw.Close()
	})

	ni.MouseUp().Attach(func(x, y int, button walk.MouseButton) {
		if button != walk.LeftButton {
			return
		}
		wasEnrolled := app.IsEnrolled()
		setBusy(true)
		go func() {
			err := app.LoginOrEnroll(ctx)
			mw.Synchronize(func() {
				setBusy(false)
				if err != nil {
					showError("Login failed", err)
					return
				}
				if !wasEnrolled {
					showInfo("Device enrolled and synced")
				}
			})
		}()
	})

	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		_ = ni.SetVisible(false)
	})

	if err := ni.SetVisible(true); err != nil {
		return err
	}
	log.Printf("tray icon ready; log file: %s", app.LogPath)
	refreshStatus()

	go func() {
		<-ctx.Done()
		mw.Synchronize(func() {
			_ = mw.Close()
		})
	}()

	mw.Run()
	return nil
}

func keywardIcon() (*walk.Icon, error) {
	img, err := png.Decode(bytes.NewReader(keywardTrayIconPNG))
	if err != nil {
		return nil, err
	}
	return walk.NewIconFromImage(img)
}

func newTrayAction(text string, enabled bool, handler func()) (*walk.Action, error) {
	action := walk.NewAction()
	if err := action.SetText(escapeMenuText(text)); err != nil {
		return nil, err
	}
	if err := action.SetEnabled(enabled); err != nil {
		return nil, err
	}
	if handler != nil {
		action.Triggered().Attach(handler)
	}
	return action, nil
}

func escapeMenuText(text string) string {
	return strings.ReplaceAll(text, "&", "&&")
}
