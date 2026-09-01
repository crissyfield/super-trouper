// Package frida provides a minimal Frida Core client.
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
	"sync"
	"unsafe"
)

// Config contains the remote Frida server configuration.
type Config struct {
	Address string
}

// Process describes a process running on a Frida device.
type Process struct {
	PID  uint
	Name string
}

// Application describes an application installed on a Frida device.
type Application struct {
	Identifier string
	Name       string
	PID        uint
	Running    bool
}

// Client is a connection to a remote Frida server.
type Client struct {
	mu       sync.Mutex
	manager  *C.FridaDeviceManager
	device   *C.FridaDevice
	version  string
	deviceID string
	name     string
	closed   bool
}

var library struct {
	sync.Mutex
	clients uint
}

// New connects to the Frida server at config.Address.
func New(ctx context.Context, config Config) (*Client, error) {
	if config.Address == "" {
		return nil, errors.New("Frida server address is required")
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("connect to Frida server: %w", err)
	}

	acquireLibrary()

	manager := C.frida_device_manager_new_with_socket_backend_only()
	if manager == nil {
		releaseLibrary()
		return nil, errors.New("create Frida device manager")
	}

	cancellable, releaseCancellable := newCancellable(ctx)

	address := C.CString(config.Address)
	defer C.free(unsafe.Pointer(address))

	var gErr *C.GError
	device := C.frida_device_manager_add_remote_device_sync(manager, address, nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		releaseCancellable()
		unref(unsafe.Pointer(manager))
		releaseLibrary()
		return nil, fmt.Errorf("connect to Frida server at %q: %w", config.Address, err)
	}

	if device == nil {
		releaseCancellable()
		unref(unsafe.Pointer(manager))
		releaseLibrary()
		return nil, fmt.Errorf("connect to Frida server at %q: no device returned", config.Address)
	}
	releaseCancellable()

	return &Client{
		manager:  manager,
		device:   device,
		version:  C.GoString(C.frida_version_string()),
		deviceID: C.GoString(C.frida_device_get_id(device)),
		name:     C.GoString(C.frida_device_get_name(device)),
	}, nil
}

// Version returns the Frida Core version used by the client.
func (c *Client) Version() string {
	return c.version
}

// DeviceID returns the remote device identifier.
func (c *Client) DeviceID() string {
	return c.deviceID
}

// DeviceName returns the remote device name.
func (c *Client) DeviceName() string {
	return c.name
}

// ListApplications returns the applications installed on the remote device.
func (c *Client) ListApplications(ctx context.Context) ([]Application, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errors.New("Frida client is closed")
	}

	cancellable, cancel := newCancellable(ctx)
	defer cancel()

	var gErr *C.GError
	list := C.frida_device_enumerate_applications_sync(c.device, nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("enumerate applications: %w", err)
	}

	if list == nil {
		return nil, errors.New("enumerate applications: no application list returned")
	}
	defer unref(unsafe.Pointer(list))

	count := int(C.frida_application_list_size(list))
	applications := make([]Application, 0, count)

	for index := 0; index < count; index++ {
		application := C.frida_application_list_get(list, C.gint(index))
		if application == nil {
			continue
		}

		pid := uint(C.frida_application_get_pid(application))
		applications = append(applications, Application{
			Identifier: C.GoString(C.frida_application_get_identifier(application)),
			Name:       C.GoString(C.frida_application_get_name(application)),
			PID:        pid,
			Running:    pid != 0,
		})
		unref(unsafe.Pointer(application))
	}

	return applications, nil
}

// ListProcesses returns the processes running on the remote device.
func (c *Client) ListProcesses(ctx context.Context) ([]Process, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errors.New("Frida client is closed")
	}

	cancellable, cancel := newCancellable(ctx)
	defer cancel()

	var gErr *C.GError
	list := C.frida_device_enumerate_processes_sync(c.device, nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("enumerate processes: %w", err)
	}

	if list == nil {
		return nil, errors.New("enumerate processes: no process list returned")
	}
	defer unref(unsafe.Pointer(list))

	count := int(C.frida_process_list_size(list))
	processes := make([]Process, 0, count)

	for index := 0; index < count; index++ {
		process := C.frida_process_list_get(list, C.gint(index))
		if process == nil {
			continue
		}

		processes = append(processes, Process{
			PID:  uint(C.frida_process_get_pid(process)),
			Name: C.GoString(C.frida_process_get_name(process)),
		})
		unref(unsafe.Pointer(process))
	}

	return processes, nil
}

// Close disconnects from the remote server and releases Frida Core resources.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	cancellable, releaseCancellable := newCancellable(ctx)

	var gErr *C.GError
	C.frida_device_manager_close_sync(c.manager, cancellable, &gErr)

	if c.device != nil {
		unref(unsafe.Pointer(c.device))
		c.device = nil
	}

	if c.manager != nil {
		unref(unsafe.Pointer(c.manager))
		c.manager = nil
	}

	closeErr := consumeGError(gErr)

	// Frida deinitializes GLib and GIO, so free their objects first.
	releaseCancellable()
	releaseLibrary()

	if closeErr != nil {
		return fmt.Errorf("close Frida device manager: %w", closeErr)
	}

	return nil
}

func acquireLibrary() {
	library.Lock()
	defer library.Unlock()

	if library.clients == 0 {
		C.frida_init()
	}

	library.clients++
}

func releaseLibrary() {
	library.Lock()
	defer library.Unlock()

	library.clients--
	if library.clients == 0 {
		C.frida_deinit()
	}
}

func newCancellable(ctx context.Context) (*C.GCancellable, func()) {
	cancellable := C.g_cancellable_new()
	done := make(chan struct{})

	stop := context.AfterFunc(ctx, func() {
		C.g_cancellable_cancel(cancellable)
		close(done)
	})

	return cancellable, func() {
		if !stop() {
			<-done
		}

		C.g_object_unref(C.gpointer(unsafe.Pointer(cancellable)))
	}
}

func unref(value unsafe.Pointer) {
	C.frida_unref(C.gpointer(value))
}

func consumeGError(gErr *C.GError) error {
	if gErr == nil {
		return nil
	}
	defer C.g_error_free(gErr)

	return errors.New(C.GoString((*C.char)(unsafe.Pointer(gErr.message))))
}
