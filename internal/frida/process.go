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
