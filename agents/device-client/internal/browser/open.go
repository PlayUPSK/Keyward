package browser

import (
	"os/exec"
	"runtime"

	"github.com/playup/keyward/agents/device-client/internal/process"
)

func Open(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	process.HideWindow(cmd)
	return cmd.Start()
}
