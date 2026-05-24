//go:build windows

package deviceinfo

import (
	"context"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const netSetupDomainName = 3
const tpmVersionNone = 0

var (
	kernel32DLL                    = windows.NewLazySystemDLL("kernel32.dll")
	procGetFirmwareEnvironmentVar = kernel32DLL.NewProc("GetFirmwareEnvironmentVariableW")
	tbsDLL                         = windows.NewLazySystemDLL("tbs.dll")
	procTbsiGetDeviceInfo          = tbsDLL.NewProc("Tbsi_GetDeviceInfo")
)

type tbsDeviceInfo struct {
	StructVersion    uint32
	TPMVersion       uint32
	TPMInterfaceType uint32
	TPMImpRevision   uint32
}

func collectPlatform(ctx context.Context, info *Info) {
	info.OSVersion = firstNonEmpty(
		registryString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "DisplayVersion"),
		registryString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ReleaseId"),
	)
	if build := registryString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "CurrentBuild"); build != "" {
		if info.OSVersion == "" {
			info.OSVersion = build
		} else {
			info.OSVersion += " build " + build
		}
	}
	info.Vendor = firstNonEmpty(
		registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer"),
		registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardManufacturer"),
		registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "BIOSVendor"),
	)
	info.Model = firstNonEmpty(
		registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName"),
		registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "BaseBoardProduct"),
		registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemFamily"),
	)

	machineGUID := registryString(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, "MachineGuid")
	biosVersion := registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "BIOSVersion")
	systemSKU := registryString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemSKU")

	setHashed(info.Identifiers, "machine_guid", machineGUID)
	setHashed(info.Identifiers, "bios_version", biosVersion)
	setHashed(info.Identifiers, "system_sku", systemSKU)
	info.MachineIDHash = hashIdentifier(machineGUID)
	info.HardwareUUIDHash = hashIdentifier(firstNonEmpty(machineGUID, biosVersion, systemSKU))
	if domain, joined := windowsDomainJoin(); joined {
		info.DomainJoined = true
		info.Domain = domain
		info.DirectoryService = "active_directory"
	}
	setSecurity(info, "secure_boot", windowsSecureBootEnabled())
	setSecurity(info, "firewall", windowsFirewallEnabled())
	setSecurity(info, "screen_lock", registryString(registry.CURRENT_USER, `Control Panel\Desktop`, "ScreenSaveActive") == "1")
	setSecurity(info, "mdm_enrolled", windowsMDMEnrolled())
	setSecurity(info, "tpm_present", windowsTPMPresent())
	setSecurity(info, "antivirus", registryKeyExists(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender`))
	setSecurity(info, "disk_encryption", windowsBitLockerEnabled(ctx))
	_ = ctx
}

func windowsDomainJoin() (string, bool) {
	netapi := windows.NewLazySystemDLL("netapi32.dll")
	netGetJoinInformation := netapi.NewProc("NetGetJoinInformation")
	netApiBufferFree := netapi.NewProc("NetApiBufferFree")

	var name *uint16
	var status uint32
	ret, _, _ := netGetJoinInformation.Call(
		0,
		uintptr(unsafe.Pointer(&name)),
		uintptr(unsafe.Pointer(&status)),
	)
	if name != nil {
		defer netApiBufferFree.Call(uintptr(unsafe.Pointer(name)))
	}
	if ret != 0 || status != netSetupDomainName || name == nil {
		return "", false
	}
	domain := windows.UTF16PtrToString(name)
	return domain, domain != ""
}

func registryString(root registry.Key, path string, name string) string {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		key, err = registry.OpenKey(root, path, registry.QUERY_VALUE)
		if err != nil {
			return ""
		}
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}

func registryDword(root registry.Key, path string, name string) uint64 {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		key, err = registry.OpenKey(root, path, registry.QUERY_VALUE)
		if err != nil {
			return 0
		}
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return value
}

func registryKeyExists(root registry.Key, path string) bool {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		key, err = registry.OpenKey(root, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			return false
		}
	}
	key.Close()
	return true
}

func registryHasSubkeys(root registry.Key, path string) bool {
	key, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		key, err = registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			return false
		}
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(1)
	return err == nil && len(names) > 0
}

func windowsMDMEnrolled() bool {
	key, err := openRegistryKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, name := range names {
		child, err := openRegistryKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		enrollmentType, _, valueErr := child.GetIntegerValue("EnrollmentType")
		child.Close()
		if valueErr == nil && enrollmentType == 6 {
			return true
		}
	}
	return false
}

func windowsFirewallEnabled() bool {
	profiles := []string{"DomainProfile", "StandardProfile", "PublicProfile"}
	for _, profile := range profiles {
		if registryDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`+profile, "EnableFirewall") != 1 {
			return false
		}
	}
	return true
}

func openRegistryKey(root registry.Key, path string, access uint32) (registry.Key, error) {
	key, err := registry.OpenKey(root, path, access|registry.WOW64_64KEY)
	if err == nil {
		return key, nil
	}
	return registry.OpenKey(root, path, access)
}

func windowsSecureBootEnabled() bool {
	name, err := windows.UTF16PtrFromString("SecureBoot")
	if err == nil {
		guid, guidErr := windows.UTF16PtrFromString("{8be4df61-93ca-11d2-aa0d-00e098032b8c}")
		if guidErr == nil {
			var value [1]byte
			ret, _, callErr := procGetFirmwareEnvironmentVar.Call(
				uintptr(unsafe.Pointer(name)),
				uintptr(unsafe.Pointer(guid)),
				uintptr(unsafe.Pointer(&value[0])),
				uintptr(len(value)),
			)
			if ret == 1 {
				return value[0] == 1
			}
			if callErr == windows.ERROR_INVALID_FUNCTION {
				return false
			}
		}
	}
	return registryDword(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled") == 1
}

func windowsTPMPresent() bool {
	var info tbsDeviceInfo
	size := uint32(unsafe.Sizeof(info))
	ret, _, _ := procTbsiGetDeviceInfo.Call(
		uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&info)),
	)
	if ret == 0 && info.TPMVersion != tpmVersionNone {
		return true
	}

	return registryKeyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\TPM\WMI`) ||
		registryKeyExists(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\TPM`)
}

func windowsBitLockerEnabled(ctx context.Context) bool {
	output := commandOutput(ctx, "manage-bde", "-status", "C:")
	return containsFold(output, "Protection Status:    Protection On") || containsFold(output, "Protection On")
}

func containsFold(value string, fragment string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(fragment))
}
