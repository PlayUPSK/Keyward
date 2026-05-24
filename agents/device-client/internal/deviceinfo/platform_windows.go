//go:build windows

package deviceinfo

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const netSetupDomainName = 3

func collectPlatform(ctx context.Context, info *Info) {
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
