//go:build !windows

package tray

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/playup/keyward/agents/device-client/internal/trayapp"
)

func Run(ctx context.Context, app *trayapp.App) error {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println()
		fmt.Println("Keyward Client")
		fmt.Println(app.StatusLine())
		fmt.Println()
		fmt.Println("1) Sync access")
		fmt.Printf("2) %s\n", app.LoginActionLabel())
		fmt.Println("3) Logout local device")
		fmt.Println("4) Quit")
		fmt.Print("> ")

		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		switch strings.TrimSpace(line) {
		case "1":
			if err := app.Sync(ctx); err != nil {
				fmt.Printf("sync failed: %v\n", err)
			} else {
				fmt.Println("sync complete")
			}
		case "2":
			wasEnrolled := app.IsEnrolled()
			if err := app.LoginOrEnroll(ctx); err != nil {
				fmt.Printf("open %s failed: %v\n", strings.ToLower(app.LoginActionLabel()), err)
			} else if !wasEnrolled {
				fmt.Println("device enrolled and synced")
			}
		case "3":
			if err := app.Logout(); err != nil {
				fmt.Printf("logout failed: %v\n", err)
			} else {
				fmt.Println("local device state cleared")
			}
		case "4", "q", "quit":
			return nil
		default:
			fmt.Println("unknown option")
		}
	}
}
