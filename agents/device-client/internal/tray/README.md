# Tray Backend

`cmd/keyward-tray` now uses a native Windows tray backend and keeps a portable
console fallback for non-Windows targets so it still compiles in headless
Linux, CI, and macOS.

The production tray backend should implement the same actions through a native
tray library:

- status label
- sync access
- open login when already enrolled, otherwise run the full browser enrollment flow and sync access
- logout local device
- quit

Recommended next implementation options for other platforms:

- `github.com/getlantern/systray` for a minimal tray-only app where `cgo` is
	acceptable.
- Wails for a richer settings/status window plus tray.
- Fyne if a cross-platform native-ish settings window is preferred.

Keep `internal/trayapp.App` as the business logic boundary. Native tray code
should call `App.Sync`, `App.OpenLoginOrEnroll`, and `App.Logout` instead of
duplicating state or HTTP logic.
