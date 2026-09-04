package frida

/*
#include <frida-core.h>
*/
import "C"

// DeviceType identifies how Frida discovered a device.
type DeviceType string

// Device types reported by Frida.
const (
	// DeviceTypeLocal indicates a device that is local to the host machine.
	DeviceTypeLocal DeviceType = "local"

	// DeviceTypeRemote indicates a device that is connected to the host machine over a network.
	DeviceTypeRemote DeviceType = "remote"

	// DeviceTypeUSB indicates a device that is connected to the host machine over USB.
	DeviceTypeUSB DeviceType = "usb"

	// DeviceTypeUnknown indicates a device that is of an unknown type.
	DeviceTypeUnknown DeviceType = "unknown"
)

// deviceTypeFromFrida converts a C.FridaDeviceType to a Go DeviceType.
func deviceTypeFromFrida(deviceType C.FridaDeviceType) DeviceType {
	switch deviceType {
	case C.FRIDA_DEVICE_TYPE_LOCAL:
		return DeviceTypeLocal
	case C.FRIDA_DEVICE_TYPE_REMOTE:
		return DeviceTypeRemote
	case C.FRIDA_DEVICE_TYPE_USB:
		return DeviceTypeUSB
	default:
		return DeviceTypeUnknown
	}
}

// deviceTypeToFrida converts a Go DeviceType to a C.FridaDeviceType, reporting whether the device type is
// valid.
func deviceTypeToFrida(dtype DeviceType) (C.FridaDeviceType, bool) {
	switch dtype {
	case DeviceTypeLocal:
		return C.FRIDA_DEVICE_TYPE_LOCAL, true
	case DeviceTypeRemote:
		return C.FRIDA_DEVICE_TYPE_REMOTE, true
	case DeviceTypeUSB:
		return C.FRIDA_DEVICE_TYPE_USB, true
	case DeviceTypeUnknown:
		return 0, true
	default:
		return 0, false
	}
}
