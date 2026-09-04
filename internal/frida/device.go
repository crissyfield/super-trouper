package frida

/*
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

// errDeviceClosed indicates that the device is already closed.
var errDeviceClosed = errors.New("device already closed")

// Device is a connection to a Frida device.
type Device struct {
	mu       sync.Mutex        // Guards device state.
	closed   bool              // Whether resources were released.
	logger   *slog.Logger      // Logger for library events.
	manager  *Manager          // Parent Frida manager.
	handle   *C.FridaDevice    // Native Frida device handle.
	id       string            // Frida device ID.
	name     string            // Human-readable device name.
	dtype    DeviceType        // Connection transport type.
	sessions map[uint]*Session // Attached process sessions keyed by PID.
}

// newDevice creates a device instance around a native Frida device handle.
func newDevice(manager *Manager, handle *C.FridaDevice) *Device {
	// Return Device instance
	return &Device{
		logger:   manager.logger,
		manager:  manager,
		handle:   handle,
		id:       C.GoString(C.frida_device_get_id(handle)),
		name:     C.GoString(C.frida_device_get_name(handle)),
		dtype:    deviceTypeFromFrida(C.frida_device_get_dtype(handle)),
		sessions: make(map[uint]*Session),
	}
}

// Close disconnects from the Frida device and releases resources.
func (d *Device) Close(ctx context.Context) error {
	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if already closed
	if d.closed {
		return nil
	}

	d.closed = true

	// Report active sessions instead of closing them
	var closeErr error

	if len(d.sessions) != 0 {
		d.logger.Error("Active sessions remain", slog.Int("count", len(d.sessions)))
		closeErr = fmt.Errorf("active sessions remain [count=%d]", len(d.sessions))
	}

	// Clean up
	C.frida_unref(C.gpointer(unsafe.Pointer(d.handle)))
	d.handle = nil

	d.manager.releaseDevice(d)
	d.manager = nil

	return closeErr
}

// releaseSession removes a session from the device's active sessions map.
func (d *Device) releaseSession(session *Session) {
	// Synchronize delete
	d.mu.Lock()
	delete(d.sessions, session.pid)
	d.mu.Unlock()
}

// ID returns the Frida device ID.
func (d *Device) ID() string {
	return d.id
}

// Name returns the human-readable device name.
func (d *Device) Name() string {
	return d.name
}

// Type returns the connection transport type.
func (d *Device) Type() DeviceType {
	return d.dtype
}

// Attach attaches to the process with the given PID and returns the new session.
func (d *Device) Attach(ctx context.Context, pid uint) (*Session, error) {
	// Validate input
	if pid == 0 {
		return nil, errors.New("no pid given")
	}

	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return nil, errDeviceClosed
	}

	// Early exit if the process already has an attached session
	if d.sessions[pid] != nil {
		return nil, fmt.Errorf("already attached to process [pid=%d]", pid)
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Attach to process
	var gErr *C.GError

	handle := C.frida_device_attach_sync(d.handle, C.guint(pid), nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("attach to process [pid=%d]: %w", pid, err)
	}

	if handle == nil {
		return nil, fmt.Errorf("attach to process [pid=%d]: empty", pid)
	}

	// Create session instance
	session := newSession(d, handle, pid)
	d.sessions[pid] = session

	return session, nil
}
