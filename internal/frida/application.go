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

// Application describes an application installed on a Frida device.
type Application struct {
	Identifier string // Application bundle identifier.
	Name       string // Application name.
	PID        uint   // Running process ID.
	Running    bool   // Whether the application is running.
}

// ListApplications returns the applications installed on the remote device.
func (d *Device) ListApplications(ctx context.Context) ([]Application, error) {
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

	// Enumerate applications
	var gErr *C.GError

	list := C.frida_device_enumerate_applications_sync(d.handle, nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("enumerate applications: %w", err)
	}

	if list == nil {
		// No apps found
		return nil, nil
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(list)))

	// Create an application for each entry
	count := int(C.frida_application_list_size(list))
	apps := make([]Application, 0, count)

	for index := range count {
		// Get app from list
		app := C.frida_application_list_get(list, C.gint(index))
		if app == nil {
			continue
		}

		// Append app to list
		pid := uint(C.frida_application_get_pid(app))

		apps = append(apps, Application{
			Identifier: C.GoString(C.frida_application_get_identifier(app)),
			Name:       C.GoString(C.frida_application_get_name(app)),
			PID:        pid,
			Running:    pid != 0,
		})

		C.frida_unref(C.gpointer(unsafe.Pointer(app)))
	}

	return apps, nil
}
