package frida

/*
#include <frida-core.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"unsafe"
)

// Process describes a process running on a Frida device.
type Process struct {
	PID  uint   // Operating system process ID.
	Name string // Process name.
}

// ProcessMatchOption configures a single aspect of a process match query.
type ProcessMatchOption func(*processMatchOptions)

// processMatchOptions holds the options for matching a process.
type processMatchOptions struct {
	timeout uint // Milliseconds to wait for a match, zero to not wait.
}

// WithProcessMatchTimeout sets how long to wait for a process to match before giving up (in seconds). Zero, the
// default, does not wait.
func WithProcessMatchTimeout(timeout uint) ProcessMatchOption {
	return func(options *processMatchOptions) { options.timeout = timeout }
}

// ListProcesses returns the processes running on the remote device.
func (d *Device) ListProcesses(ctx context.Context) ([]Process, error) {
	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return nil, errors.New("already closed")
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Enumerate processes
	var gErr *C.GError

	list := C.frida_device_enumerate_processes_sync(d.handle, nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("enumerate processes: %w", err)
	}

	if list == nil {
		// No processes found
		return nil, nil
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(list)))

	count := int(C.frida_process_list_size(list))
	processes := make([]Process, 0, count)

	// Create a process for each entry
	for index := range count {
		// Get process from list
		process := C.frida_process_list_get(list, C.gint(index))
		if process == nil {
			continue
		}

		// Append process to list
		processes = append(processes, Process{
			PID:  uint(C.frida_process_get_pid(process)),
			Name: C.GoString(C.frida_process_get_name(process)),
		})

		C.frida_unref(C.gpointer(unsafe.Pointer(process)))
	}

	return processes, nil
}

// FindProcessByName returns the process with the given name, or nil if no such process is running on the remote
// device. Name matching is case-insensitive, and the first matching process wins.
func (d *Device) FindProcessByName(ctx context.Context, name string, opts ...ProcessMatchOption) (*Process, error) {
	// Validate input
	if name == "" {
		return nil, errors.New("invalid name")
	}

	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return nil, errDeviceClosed
	}

	// Assemble match options
	var options *C.FridaProcessMatchOptions
	var config processMatchOptions

	for _, opt := range opts {
		opt(&config)
	}

	if config.timeout != 0 {
		// Create match options
		options = C.frida_process_match_options_new()
		defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

		// Set timeout
		C.frida_process_match_options_set_timeout(options, C.gint(config.timeout))
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Find process by name
	var gErr *C.GError

	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	handle := C.frida_device_find_process_by_name_sync(d.handle, cname, options, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("find process [name=%s]: %w", name, err)
	}

	if handle == nil {
		// No process found
		return nil, nil
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(handle)))

	// Copy process into a Go instance
	return &Process{
		PID:  uint(C.frida_process_get_pid(handle)),
		Name: C.GoString(C.frida_process_get_name(handle)),
	}, nil
}

// FindProcessByPID returns the process with the given PID, or nil if no such process is running on the remote device.
func (d *Device) FindProcessByPID(ctx context.Context, pid uint) (*Process, error) {
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

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Find process by PID
	var gErr *C.GError

	handle := C.frida_device_find_process_by_pid_sync(d.handle, C.guint(pid), nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("find process [pid=%d]: %w", pid, err)
	}

	if handle == nil {
		// No process found
		return nil, nil
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(handle)))

	// Copy process into a Go instance
	return &Process{
		PID:  uint(C.frida_process_get_pid(handle)),
		Name: C.GoString(C.frida_process_get_name(handle)),
	}, nil
}
