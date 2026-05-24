package deviceinfo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/playup/keyward/agents/device-client/internal/process"
)

type Info struct {
	CollectedAt       string            `json:"collected_at"`
	Hostname          string            `json:"hostname,omitempty"`
	OS                string            `json:"os"`
	Arch              string            `json:"arch"`
	User              string            `json:"local_user,omitempty"`
	Vendor            string            `json:"vendor,omitempty"`
	Model             string            `json:"model,omitempty"`
	SerialHash        string            `json:"serial_hash,omitempty"`
	SerialSuffix      string            `json:"serial_suffix,omitempty"`
	MachineIDHash     string            `json:"machine_id_hash,omitempty"`
	HardwareUUIDHash  string            `json:"hardware_uuid_hash,omitempty"`
	DeviceFingerprint string            `json:"device_fingerprint,omitempty"`
	DomainJoined      bool              `json:"domain_joined,omitempty"`
	Domain            string            `json:"domain,omitempty"`
	DirectoryService  string            `json:"directory_service,omitempty"`
	Identifiers       map[string]string `json:"identifiers,omitempty"`
}

func Collect(ctx context.Context) map[string]any {
	info := Info{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		Identifiers: map[string]string{},
	}
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}
	if currentUser, err := user.Current(); err == nil {
		info.User = currentUser.Username
	}

	collectPlatform(ctx, &info)

	info.DeviceFingerprint = fingerprint(info)
	return map[string]any{
		"hostname":           info.Hostname,
		"os":                 info.OS,
		"arch":               info.Arch,
		"local_user":         info.User,
		"device_fingerprint": info.DeviceFingerprint,
		"hardware": map[string]any{
			"vendor":             info.Vendor,
			"model":              info.Model,
			"serial_hash":        info.SerialHash,
			"serial_suffix":      info.SerialSuffix,
			"machine_id_hash":    info.MachineIDHash,
			"hardware_uuid_hash": info.HardwareUUIDHash,
			"identifiers":        info.Identifiers,
		},
		"enterprise": map[string]any{
			"domain_joined":     info.DomainJoined,
			"domain":            info.Domain,
			"directory_service": info.DirectoryService,
		},
		"agent": map[string]any{
			"collected_at": info.CollectedAt,
			"collector":    "keyward-ssh-deviceinfo-v1",
		},
	}
}

func collectDarwin(ctx context.Context, info *Info) {
	output := commandOutput(ctx, "system_profiler", "SPHardwareDataType")
	values := parseColonLines(output)
	info.Vendor = "Apple"
	info.Model = values["Model Name"]
	serial := values["Serial Number (system)"]
	uuid := values["Hardware UUID"]
	setHashed(info.Identifiers, "system_serial", serial)
	setHashed(info.Identifiers, "hardware_uuid", uuid)
	info.SerialHash = hashIdentifier(serial)
	info.SerialSuffix = suffix(serial, 4)
	info.HardwareUUIDHash = hashIdentifier(uuid)
	domainOutput := commandOutput(ctx, "dsconfigad", "-show")
	domainValues := parseEqualsLines(domainOutput)
	if domain := domainValues["Active Directory Domain"]; domain != "" {
		info.DomainJoined = true
		info.Domain = domain
		info.DirectoryService = "active_directory"
	}
}

func collectLinux(ctx context.Context, info *Info) {
	info.Vendor = readTrimmed("/sys/class/dmi/id/sys_vendor")
	info.Model = firstNonEmpty(readTrimmed("/sys/class/dmi/id/product_name"), readTrimmed("/sys/class/dmi/id/board_name"))
	serial := firstNonEmpty(readTrimmed("/sys/class/dmi/id/product_serial"), readTrimmed("/sys/class/dmi/id/board_serial"))
	uuid := readTrimmed("/sys/class/dmi/id/product_uuid")
	machineID := firstNonEmpty(readTrimmed("/etc/machine-id"), readTrimmed("/var/lib/dbus/machine-id"))
	setHashed(info.Identifiers, "dmi_serial", serial)
	setHashed(info.Identifiers, "dmi_uuid", uuid)
	setHashed(info.Identifiers, "machine_id", machineID)
	info.SerialHash = hashIdentifier(serial)
	info.SerialSuffix = suffix(serial, 4)
	info.HardwareUUIDHash = hashIdentifier(uuid)
	info.MachineIDHash = hashIdentifier(machineID)
	realmOutput := commandOutput(ctx, "realm", "list")
	realmValues := parseColonLines(realmOutput)
	if domain := realmValues["domain-name"]; domain != "" {
		info.DomainJoined = true
		info.Domain = domain
		info.DirectoryService = "realm"
	}
}

func commandOutput(ctx context.Context, name string, args ...string) string {
	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, name, args...)
	process.HideWindow(cmd)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func parseColonLines(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return values
}

func parseEqualsLines(output string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return values
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func setHashed(values map[string]string, key string, value string) {
	if hashed := hashIdentifier(value); hashed != "" {
		values[key+"_hash"] = hashed
	}
}

func hashIdentifier(value string) string {
	cleaned := strings.TrimSpace(value)
	if cleaned == "" || strings.EqualFold(cleaned, "none") || strings.EqualFold(cleaned, "to be filled by o.e.m.") {
		return ""
	}
	sum := sha256.Sum256([]byte("keyward-device-fingerprint-v1:" + cleaned))
	return hex.EncodeToString(sum[:])
}

func fingerprint(info Info) string {
	parts := []string{
		info.OS,
		info.Arch,
		info.Vendor,
		info.Model,
		info.SerialHash,
		info.HardwareUUIDHash,
		info.MachineIDHash,
		info.Hostname,
	}
	return hashIdentifier(strings.Join(parts, "|"))
}

func suffix(value string, n int) string {
	cleaned := strings.TrimSpace(value)
	if cleaned == "" || len(cleaned) <= n {
		return cleaned
	}
	return cleaned[len(cleaned)-n:]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
