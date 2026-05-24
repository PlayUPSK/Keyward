//go:build windows

package presence

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/lxn/win"
	"github.com/playup/keyward/agents/device-client/internal/config"
	"golang.org/x/sys/windows"
)

const (
	windowsHelloRPID          = "keyward.local"
	windowsHelloOrigin        = "https://keyward.local"
	windowsHelloCredentialTyp = "public-key"
	windowsHelloHashAlg       = "SHA-256"

	webAuthnRPEntityInformationVersion       = 1
	webAuthnUserEntityInformationVersion     = 1
	webAuthnClientDataVersion                = 1
	webAuthnCOSECredentialParameterVersion   = 1
	webAuthnCredentialVersion                = 1
	webAuthnMakeCredentialOptionsVersion     = 1
	webAuthnGetAssertionOptionsVersion       = 1
	webAuthnCredentialTypePublicKeyAlgorithm = -7

	webAuthnAuthenticatorAttachmentPlatform = 1
	webAuthnUserVerificationRequired        = 1
	webAuthnAttestationConveyanceNone       = 1
)

var (
	webAuthnDLL              = windows.NewLazySystemDLL("webauthn.dll")
	webAuthnVersion          = webAuthnDLL.NewProc("WebAuthNGetApiVersionNumber")
	webAuthnIsUVPAA          = webAuthnDLL.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	webAuthnMakeCredential   = webAuthnDLL.NewProc("WebAuthNAuthenticatorMakeCredential")
	webAuthnGetAssertion     = webAuthnDLL.NewProc("WebAuthNAuthenticatorGetAssertion")
	webAuthnFreeCredential   = webAuthnDLL.NewProc("WebAuthNFreeCredentialAttestation")
	webAuthnFreeAssertion    = webAuthnDLL.NewProc("WebAuthNFreeAssertion")
	webAuthnGetErrorName     = webAuthnDLL.NewProc("WebAuthNGetErrorName")
	webAuthnWindowClass      = windows.StringToUTF16("KeywardWebAuthnWindow")
	webAuthnWindowTitle      = windows.StringToUTF16("Keyward")
	webAuthnWindowProc       = windows.NewCallback(webAuthnWindowWndProc)
	webAuthnWindowRegister   sync.Once
	webAuthnWindowRegisterMu sync.Mutex
	webAuthnWindowErr        error
)

type windowsHelloCredential struct {
	RPID         string `json:"rp_id"`
	UserID       string `json:"user_id"`
	CredentialID string `json:"credential_id"`
	CreatedAt    string `json:"created_at"`
}

type webAuthnRPEntityInformation struct {
	dwVersion uint32
	pwszID    *uint16
	pwszName  *uint16
	pwszIcon  *uint16
}

type webAuthnUserEntityInformation struct {
	dwVersion       uint32
	cbID            uint32
	pbID            *byte
	pwszName        *uint16
	pwszIcon        *uint16
	pwszDisplayName *uint16
}

type webAuthnClientData struct {
	dwVersion        uint32
	cbClientDataJSON uint32
	pbClientDataJSON *byte
	pwszHashAlgID    *uint16
}

type webAuthnCOSECredentialParameter struct {
	dwVersion          uint32
	pwszCredentialType *uint16
	lAlg               int32
}

type webAuthnCOSECredentialParameters struct {
	cCredentialParameters uint32
	pCredentialParameters *webAuthnCOSECredentialParameter
}

type webAuthnCredential struct {
	dwVersion          uint32
	cbID               uint32
	pbID               *byte
	pwszCredentialType *uint16
}

type webAuthnCredentials struct {
	cCredentials uint32
	pCredentials *webAuthnCredential
}

type webAuthnExtension struct {
	pwszExtensionIdentifier *uint16
	cbExtension             uint32
	pvExtension             unsafe.Pointer
}

type webAuthnExtensions struct {
	cExtensions uint32
	pExtensions *webAuthnExtension
}

type webAuthnMakeCredentialOptionsV1 struct {
	dwVersion                         uint32
	dwTimeoutMilliseconds             uint32
	credentialList                    webAuthnCredentials
	extensions                        webAuthnExtensions
	dwAuthenticatorAttachment         uint32
	bRequireResidentKey               int32
	dwUserVerificationRequirement     uint32
	dwAttestationConveyancePreference uint32
	dwFlags                           uint32
}

type webAuthnGetAssertionOptionsV1 struct {
	dwVersion                     uint32
	dwTimeoutMilliseconds         uint32
	credentialList                webAuthnCredentials
	extensions                    webAuthnExtensions
	dwAuthenticatorAttachment     uint32
	dwUserVerificationRequirement uint32
	dwFlags                       uint32
}

type webAuthnCredentialAttestationPrefix struct {
	dwVersion               uint32
	pwszFormatType          *uint16
	cbAuthenticatorData     uint32
	pbAuthenticatorData     *byte
	cbAttestation           uint32
	pbAttestation           *byte
	dwAttestationDecodeType uint32
	pvAttestationDecode     unsafe.Pointer
	cbAttestationObject     uint32
	pbAttestationObject     *byte
	cbCredentialID          uint32
	pbCredentialID          *byte
}

type webAuthnPromptWindow struct {
	hwnd win.HWND
	done chan struct{}
}

func runWindowsHello(ctx context.Context, cfg config.Config, reason string) error {
	return runWindowsHelloWebAuthn(ctx, cfg, reason)
}

func runWindowsHelloWebAuthn(ctx context.Context, cfg config.Config, reason string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := ensureWebAuthnAvailable(); err != nil {
		return err
	}

	promptWindow, err := createWebAuthnPromptWindow()
	if err != nil {
		return err
	}
	defer promptWindow.close()

	cred, err := loadWindowsHelloCredential(cfg)
	if err != nil {
		return err
	}
	if cred == nil {
		cred, err = createWindowsHelloCredential(promptWindow.hwnd, cfg)
		if err != nil {
			return err
		}
	}

	return verifyWindowsHelloAssertion(promptWindow.hwnd, cred, reason)
}

func ensureWebAuthnAvailable() error {
	if err := webAuthnDLL.Load(); err != nil {
		return fmt.Errorf("Windows WebAuthn API is unavailable: %w", err)
	}
	if v, _, _ := webAuthnVersion.Call(); v == 0 {
		return fmt.Errorf("Windows WebAuthn API returned version 0")
	}

	var available int32
	if hr, _, _ := webAuthnIsUVPAA.Call(uintptr(unsafe.Pointer(&available))); failedHRESULT(hr) {
		return fmt.Errorf("Windows Hello/WebAuthn availability check failed: %s", formatHRESULT(hr))
	}
	if available == 0 {
		return fmt.Errorf("Windows Hello platform authenticator is not available; set up Windows Hello PIN/biometrics or use user_presence_mode=command with a security key")
	}
	return nil
}

func createWindowsHelloCredential(hwnd win.HWND, cfg config.Config) (*windowsHelloCredential, error) {
	userID := make([]byte, 32)
	if _, err := rand.Read(userID); err != nil {
		return nil, err
	}

	rpID, _ := windows.UTF16PtrFromString(windowsHelloRPID)
	rpName, _ := windows.UTF16PtrFromString("Keyward")
	userName, _ := windows.UTF16PtrFromString("local-device")
	displayName, _ := windows.UTF16PtrFromString("Local Keyward Device")
	credentialType, _ := windows.UTF16PtrFromString(windowsHelloCredentialTyp)

	rp := webAuthnRPEntityInformation{
		dwVersion: webAuthnRPEntityInformationVersion,
		pwszID:    rpID,
		pwszName:  rpName,
	}
	user := webAuthnUserEntityInformation{
		dwVersion:       webAuthnUserEntityInformationVersion,
		cbID:            uint32(len(userID)),
		pbID:            bytePtr(userID),
		pwszName:        userName,
		pwszDisplayName: displayName,
	}
	param := webAuthnCOSECredentialParameter{
		dwVersion:          webAuthnCOSECredentialParameterVersion,
		pwszCredentialType: credentialType,
		lAlg:               webAuthnCredentialTypePublicKeyAlgorithm,
	}
	params := webAuthnCOSECredentialParameters{
		cCredentialParameters: 1,
		pCredentialParameters: &param,
	}
	clientData, err := newClientData("webauthn.create", "Enroll Keyward on this device")
	if err != nil {
		return nil, err
	}
	options := webAuthnMakeCredentialOptionsV1{
		dwVersion:                         webAuthnMakeCredentialOptionsVersion,
		dwTimeoutMilliseconds:             60_000,
		dwAuthenticatorAttachment:         webAuthnAuthenticatorAttachmentPlatform,
		bRequireResidentKey:               0,
		dwUserVerificationRequirement:     webAuthnUserVerificationRequired,
		dwAttestationConveyancePreference: webAuthnAttestationConveyanceNone,
	}
	activateWebAuthnPromptWindow(hwnd)

	var attestation uintptr
	hr, _, _ := webAuthnMakeCredential.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(&rp)),
		uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(clientData)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&attestation)),
	)
	if failedHRESULT(hr) {
		return nil, fmt.Errorf("Windows Hello credential enrollment failed: %s", formatHRESULT(hr))
	}
	if attestation == 0 {
		return nil, fmt.Errorf("Windows Hello credential enrollment returned no credential")
	}
	defer webAuthnFreeCredential.Call(attestation)

	att := (*webAuthnCredentialAttestationPrefix)(unsafe.Pointer(attestation))
	if att.cbCredentialID == 0 || att.pbCredentialID == nil {
		return nil, fmt.Errorf("Windows Hello credential enrollment returned an empty credential ID")
	}

	credentialID := make([]byte, int(att.cbCredentialID))
	copy(credentialID, unsafe.Slice(att.pbCredentialID, int(att.cbCredentialID)))

	cred := &windowsHelloCredential{
		RPID:         windowsHelloRPID,
		UserID:       base64.RawURLEncoding.EncodeToString(userID),
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeWindowsHelloCredential(cfg, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

func verifyWindowsHelloAssertion(hwnd win.HWND, cred *windowsHelloCredential, reason string) error {
	if cred.RPID != windowsHelloRPID {
		return fmt.Errorf("Windows Hello credential RP mismatch")
	}

	credentialID, err := base64.RawURLEncoding.DecodeString(cred.CredentialID)
	if err != nil {
		return fmt.Errorf("invalid Windows Hello credential ID: %w", err)
	}
	if len(credentialID) == 0 {
		return fmt.Errorf("Windows Hello credential ID is empty")
	}

	rpID, _ := windows.UTF16PtrFromString(cred.RPID)
	credentialType, _ := windows.UTF16PtrFromString(windowsHelloCredentialTyp)
	credential := webAuthnCredential{
		dwVersion:          webAuthnCredentialVersion,
		cbID:               uint32(len(credentialID)),
		pbID:               bytePtr(credentialID),
		pwszCredentialType: credentialType,
	}
	credentials := webAuthnCredentials{
		cCredentials: 1,
		pCredentials: &credential,
	}
	clientData, err := newClientData("webauthn.get", reason)
	if err != nil {
		return err
	}
	options := webAuthnGetAssertionOptionsV1{
		dwVersion:                     webAuthnGetAssertionOptionsVersion,
		dwTimeoutMilliseconds:         60_000,
		credentialList:                credentials,
		dwAuthenticatorAttachment:     webAuthnAuthenticatorAttachmentPlatform,
		dwUserVerificationRequirement: webAuthnUserVerificationRequired,
	}
	activateWebAuthnPromptWindow(hwnd)

	var assertion uintptr
	hr, _, _ := webAuthnGetAssertion.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(rpID)),
		uintptr(unsafe.Pointer(clientData)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&assertion)),
	)
	if failedHRESULT(hr) {
		return fmt.Errorf("Windows Hello verification failed: %s", formatHRESULT(hr))
	}
	if assertion == 0 {
		return fmt.Errorf("Windows Hello verification returned no assertion")
	}
	webAuthnFreeAssertion.Call(assertion)
	return nil
}

func newClientData(typ string, reason string) (*webAuthnClientData, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	body := map[string]any{
		"type":        typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      windowsHelloOrigin,
		"crossOrigin": false,
		"reason":      reason,
	}
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	hashAlg, _ := windows.UTF16PtrFromString(windowsHelloHashAlg)
	return &webAuthnClientData{
		dwVersion:        webAuthnClientDataVersion,
		cbClientDataJSON: uint32(len(jsonBytes)),
		pbClientDataJSON: bytePtr(jsonBytes),
		pwszHashAlgID:    hashAlg,
	}, nil
}

func loadWindowsHelloCredential(cfg config.Config) (*windowsHelloCredential, error) {
	data, err := os.ReadFile(windowsHelloCredentialPath(cfg))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var cred windowsHelloCredential
	if err := json.Unmarshal(data, &cred); err != nil {
		return nil, err
	}
	if cred.CredentialID == "" || cred.UserID == "" {
		return nil, fmt.Errorf("Windows Hello credential file is incomplete")
	}
	return &cred, nil
}

func writeWindowsHelloCredential(cfg config.Config, cred *windowsHelloCredential) error {
	path := windowsHelloCredentialPath(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cred, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func windowsHelloCredentialPath(cfg config.Config) string {
	return filepath.Join(filepath.Dir(cfg.DeviceKeyPath), "windows_hello_credential.json")
}

func createWebAuthnPromptWindow() (*webAuthnPromptWindow, error) {
	type result struct {
		hwnd win.HWND
		err  error
	}
	ready := make(chan result, 1)
	done := make(chan struct{})

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)

		if err := registerWebAuthnPromptWindowClass(); err != nil {
			ready <- result{err: err}
			return
		}

		width := int32(360)
		height := int32(120)
		x := (win.GetSystemMetrics(win.SM_CXSCREEN) - width) / 2
		y := (win.GetSystemMetrics(win.SM_CYSCREEN) - height) / 3
		hwnd := win.CreateWindowEx(
			win.WS_EX_TOOLWINDOW|win.WS_EX_TOPMOST,
			&webAuthnWindowClass[0],
			&webAuthnWindowTitle[0],
			win.WS_OVERLAPPEDWINDOW,
			x,
			y,
			width,
			height,
			0,
			0,
			win.GetModuleHandle(nil),
			nil,
		)
		if hwnd == 0 {
			ready <- result{err: fmt.Errorf("failed to create Windows Hello parent window")}
			return
		}
		ready <- result{hwnd: hwnd}

		var msg win.MSG
		for win.GetMessage(&msg, 0, 0, 0) > 0 {
			win.TranslateMessage(&msg)
			win.DispatchMessage(&msg)
		}
	}()

	res := <-ready
	if res.err != nil {
		return nil, res.err
	}
	return &webAuthnPromptWindow{hwnd: res.hwnd, done: done}, nil
}

func (w *webAuthnPromptWindow) close() {
	if w == nil || w.hwnd == 0 {
		return
	}
	win.PostMessage(w.hwnd, win.WM_CLOSE, 0, 0)
	<-w.done
}

func registerWebAuthnPromptWindowClass() error {
	webAuthnWindowRegister.Do(func() {
		webAuthnWindowRegisterMu.Lock()
		defer webAuthnWindowRegisterMu.Unlock()
		wc := win.WNDCLASSEX{
			CbSize:        uint32(unsafe.Sizeof(win.WNDCLASSEX{})),
			LpfnWndProc:   webAuthnWindowProc,
			HInstance:     win.GetModuleHandle(nil),
			LpszClassName: &webAuthnWindowClass[0],
		}
		if atom := win.RegisterClassEx(&wc); atom == 0 {
			webAuthnWindowErr = fmt.Errorf("failed to register Windows Hello window class")
		}
	})
	return webAuthnWindowErr
}

func activateWebAuthnPromptWindow(hwnd win.HWND) {
	win.ShowWindow(hwnd, win.SW_SHOWNORMAL)
	win.SetWindowPos(hwnd, win.HWND_TOPMOST, 0, 0, 0, 0, win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_SHOWWINDOW)
	win.BringWindowToTop(hwnd)

	currentThread := win.GetCurrentThreadId()
	foreground := win.GetForegroundWindow()
	foregroundThread := win.GetWindowThreadProcessId(foreground, nil)
	if foregroundThread != 0 && foregroundThread != currentThread {
		win.AttachThreadInput(int32(currentThread), int32(foregroundThread), true)
		defer win.AttachThreadInput(int32(currentThread), int32(foregroundThread), false)
	}
	win.SetForegroundWindow(hwnd)
}

func webAuthnWindowWndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_CLOSE:
		win.DestroyWindow(hwnd)
		return 0
	case win.WM_DESTROY:
		win.PostQuitMessage(0)
		return 0
	}
	return win.DefWindowProc(hwnd, msg, wParam, lParam)
}

func failedHRESULT(hr uintptr) bool {
	return uint32(hr)&0x80000000 != 0
}

func formatHRESULT(hr uintptr) string {
	if errName := webAuthnErrorName(hr); errName != "" {
		return fmt.Sprintf("%s (HRESULT 0x%08x)", errName, uint32(hr))
	}
	return fmt.Sprintf("HRESULT 0x%08x", uint32(hr))
}

func webAuthnErrorName(hr uintptr) string {
	if webAuthnGetErrorName.Find() != nil {
		return ""
	}
	ptr, _, _ := webAuthnGetErrorName.Call(hr)
	if ptr == 0 {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
}

func bytePtr(b []byte) *byte {
	if len(b) == 0 {
		return nil
	}
	return &b[0]
}
