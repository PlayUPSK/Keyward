package openssh

import "fmt"

func RenderTrustedUserCAConfig(trustedCAPath string) string {
	return fmt.Sprintf("TrustedUserCAKeys %s\n", trustedCAPath)
}

func RenderTrustedUserCAAndRevocationConfig(trustedCAPath string, revokedKeysPath string) string {
	return fmt.Sprintf("TrustedUserCAKeys %s\nRevokedKeys %s\n", trustedCAPath, revokedKeysPath)
}
