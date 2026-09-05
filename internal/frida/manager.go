package frida

/*
#cgo LDFLAGS: -lfrida-core -lm
#cgo darwin LDFLAGS: -lbsm -framework IOKit -framework Foundation -framework AppKit -framework Security -lpthread
#cgo linux LDFLAGS: -ldl -lrt -lresolv -lpthread
#include <stdlib.h>
#include <frida-core.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"unsafe"
)

// errManagerClosed indicates that the manager is already closed.
var errManagerClosed = errors.New("manager already closed")

// Manager owns a native Frida device manager.
type Manager struct {
	mu      sync.Mutex            // Guards manager state.
	closed  bool                  // Whether native resources were released.
	logger  *slog.Logger          // Logger for library events.
	manager *C.FridaDeviceManager // Native Frida device manager.
	devices map[*Device]struct{}  // Active devices created by this manager.
}

// ManagerOption configures a Frida manager.
type ManagerOption func(*Manager)

// WithManagerLogger sets the logger used for library events.
func WithManagerLogger(logger *slog.Logger) ManagerOption {
	return func(m *Manager) { m.logger = logger }
}

// NewManager initializes a Frida device manager.
func NewManager(options ...ManagerOption) (*Manager, error) {
	// Create manager instance with defaults
	m := &Manager{
		devices: make(map[*Device]struct{}),
	}

	// Apply options
	for _, option := range options {
		option(m)
	}

	if m.logger == nil {
		m.logger = slog.Default()
	}

	// Ensure Frida library is initialized
	acquireLibrary()

	// Create Frida device manager
	manager := C.frida_device_manager_new()
	if manager == nil {
		// Clean up
		releaseLibrary()

		return nil, errors.New("create Frida device manager")
	}

	// Assign native device manager
	m.manager = manager

	// Return manager instance
	return m, nil
}

// Close releases the Frida device manager; active devices are not closed.
func (m *Manager) Close(ctx context.Context) error {
	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Early exit if already closed
	if m.closed {
		return nil
	}

	m.closed = true

	// Report active devices instead of closing them
	var closeErr error

	if len(m.devices) != 0 {
		m.logger.Error("Active devices remain", slog.Int("count", len(m.devices)))
		closeErr = fmt.Errorf("active devices remain [count=%d]", len(m.devices))
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)

	// Close device manager
	var gErr *C.GError

	C.frida_device_manager_close_sync(m.manager, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close device manager: %w", err))
	}

	// Clean up
	releaseCancellable()

	C.frida_unref(C.gpointer(unsafe.Pointer(m.manager)))
	m.manager = nil

	releaseLibrary()

	return closeErr
}

// releaseDevice removes a device from the manager's active devices map.
func (m *Manager) releaseDevice(device *Device) {
	// Synchronize delete
	m.mu.Lock()
	delete(m.devices, device)
	m.mu.Unlock()
}

// EnumerateDevices returns the Frida devices currently detected by the host.
func (m *Manager) EnumerateDevices(ctx context.Context) ([]*Device, error) {
	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if manager is already closed
	if m.closed {
		return nil, errManagerClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Enumerate devices
	var gErr *C.GError

	list := C.frida_device_manager_enumerate_devices_sync(
		m.manager,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("enumerate devices: %w", err)
	}

	if list == nil {
		// No devices found
		return nil, nil
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(list)))

	// Create a device for each entry, keeping its native reference
	count := int(C.frida_device_list_size(list))
	devices := make([]*Device, 0, count)

	for i := range count {
		// Get device from list
		handle := C.frida_device_list_get(list, C.gint(i))
		if handle == nil {
			continue
		}

		// Create device instance
		device := newDevice(m, handle)
		m.devices[device] = struct{}{}

		// Append device to result slice
		devices = append(devices, device)
	}

	return devices, nil
}

// GetDeviceByID returns the device with the given ID.
func (m *Manager) GetDeviceByID(ctx context.Context, id string) (*Device, error) {
	// Validate input
	if id == "" {
		return nil, errors.New("device ID required")
	}

	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if manager is already closed
	if m.closed {
		return nil, errManagerClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Get device by ID
	var gErr *C.GError

	cID := C.CString(id)
	defer C.free(unsafe.Pointer(cID))

	fridaDevice := C.frida_device_manager_get_device_by_id_sync(
		m.manager,
		cID,
		0,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("get device [id=%q]: %w", id, err)
	}

	if fridaDevice == nil {
		return nil, fmt.Errorf("get device [id=%q]: empty", id)
	}

	// Create device instance
	device := newDevice(m, fridaDevice)
	m.devices[device] = struct{}{}

	return device, nil
}

// GetDeviceByType returns the first device of the given type.
func (m *Manager) GetDeviceByType(ctx context.Context, dtype DeviceType) (*Device, error) {
	// Map device type to native type
	nativeType, ok := deviceTypeToFrida(dtype)
	if !ok {
		return nil, fmt.Errorf("unknown device type [type=%q]", dtype)
	}

	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if manager is already closed
	if m.closed {
		return nil, errManagerClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Get device by type
	var gErr *C.GError

	fridaDevice := C.frida_device_manager_get_device_by_type_sync(
		m.manager,
		nativeType,
		0,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("get device [type=%q]: %w", dtype, err)
	}

	if fridaDevice == nil {
		return nil, fmt.Errorf("get device [type=%q]: empty", dtype)
	}

	// Create device instance
	device := newDevice(m, fridaDevice)
	m.devices[device] = struct{}{}

	return device, nil
}

// RemoteDeviceOption configures a single aspect of a Manager.AddRemoteDevice call.
type RemoteDeviceOption func(*remoteDeviceOptions)

// remoteDeviceOptions holds the options for a Manager.AddRemoteDevice call.
type remoteDeviceOptions struct {
	certificatePEM    string // PEM-encoded TLS certificate used to authenticate the remote device.
	token             string // Token used to authenticate with the remote device.
	origin            string // Origin header required by the remote device.
	keepaliveInterval int    // Keepalive interval for the connection, in seconds.
}

// WithRemoteDeviceCertificate sets the TLS certificate, given as PEM data, used to authenticate the remote device.
func WithRemoteDeviceCertificate(pem string) RemoteDeviceOption {
	return func(options *remoteDeviceOptions) { options.certificatePEM = pem }
}

// WithRemoteDeviceToken sets the token used to authenticate with the remote device.
func WithRemoteDeviceToken(token string) RemoteDeviceOption {
	return func(options *remoteDeviceOptions) { options.token = token }
}

// WithRemoteDeviceOrigin sets the Origin header required by the remote device.
func WithRemoteDeviceOrigin(origin string) RemoteDeviceOption {
	return func(options *remoteDeviceOptions) { options.origin = origin }
}

// WithRemoteDeviceKeepaliveInterval sets the keepalive interval, in seconds, for the connection to the remote device.
func WithRemoteDeviceKeepaliveInterval(seconds int) RemoteDeviceOption {
	return func(options *remoteDeviceOptions) { options.keepaliveInterval = seconds }
}

// AddRemoteDevice adds a remote device by its address, configured through the given options.
func (m *Manager) AddRemoteDevice(ctx context.Context, address string, opts ...RemoteDeviceOption) (*Device, error) {
	// Validate input
	if address == "" {
		return nil, errors.New("server address required")
	}

	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if manager is already closed
	if m.closed {
		return nil, errManagerClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Assemble remote device options
	var options *C.FridaRemoteDeviceOptions
	var config remoteDeviceOptions

	for _, opt := range opts {
		opt(&config)
	}

	if (config.certificatePEM != "") || (config.token != "") || (config.origin != "") || (config.keepaliveInterval != 0) {
		// Create remote device options
		options = C.frida_remote_device_options_new()
		defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

		// Set TLS certificate
		if config.certificatePEM != "" {
			// Parse certificate from PEM data
			var certErr *C.GError

			cPEM := C.CString(config.certificatePEM)
			defer C.free(unsafe.Pointer(cPEM))

			certificate := C.g_tls_certificate_new_from_pem(cPEM, C.gssize(len(config.certificatePEM)), &certErr)
			if err := consumeGError(certErr); err != nil {
				return nil, fmt.Errorf("create TLS certificate: %w", err)
			}

			defer C.g_object_unref(C.gpointer(unsafe.Pointer(certificate)))

			// Set TLS certificate
			C.frida_remote_device_options_set_certificate(options, certificate)
		}

		// Set token
		if config.token != "" {
			cToken := C.CString(config.token)
			defer C.free(unsafe.Pointer(cToken))

			C.frida_remote_device_options_set_token(options, cToken)
		}

		// Set origin
		if config.origin != "" {
			cOrigin := C.CString(config.origin)
			defer C.free(unsafe.Pointer(cOrigin))

			C.frida_remote_device_options_set_origin(options, cOrigin)
		}

		// Set keepalive interval
		if config.keepaliveInterval != 0 {
			C.frida_remote_device_options_set_keepalive_interval(options, C.gint(config.keepaliveInterval))
		}
	}

	// Connect to device by address
	var gErr *C.GError

	caddr := C.CString(address)
	defer C.free(unsafe.Pointer(caddr))

	fridaDevice := C.frida_device_manager_add_remote_device_sync(
		m.manager,
		caddr,
		options,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("connect to device [address=%q]: %w", address, err)
	}

	if fridaDevice == nil {
		return nil, fmt.Errorf("connect to device [address=%q]: empty", address)
	}

	// Create device instance
	device := newDevice(m, fridaDevice)
	m.devices[device] = struct{}{}

	return device, nil
}

// RemoveRemoteDevice removes the remote device registered with the manager at the given address.
func (m *Manager) RemoveRemoteDevice(ctx context.Context, address string) error {
	// Validate input
	if address == "" {
		return errors.New("server address required")
	}

	// Synchronize access
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if manager is already closed
	if m.closed {
		return errManagerClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Remove device by address
	var gErr *C.GError

	caddr := C.CString(address)
	defer C.free(unsafe.Pointer(caddr))

	C.frida_device_manager_remove_remote_device_sync(
		m.manager,
		caddr,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return fmt.Errorf("remove remote device [address=%q]: %w", address, err)
	}

	return nil
}
