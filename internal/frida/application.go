package frida

/*
#include <frida-core.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"unsafe"
)

// Application describes an application installed on a Frida device.
type Application struct {
	Identifier string // Application bundle identifier.
	Name       string // Application name.
	PID        uint   // Running process ID.
	Running    bool   // Whether the application is running.
}

// ApplicationOption configures a single aspect of a Device.ListApplications call.
type ApplicationOption func(*applicationOptions)

// applicationOptions holds the options for a Device.ListApplications call.
type applicationOptions struct {
	identifiers []string // Bundle identifiers requested from the device.
	names       []string // Names that applications must match.
}

// WithIdentifiers restricts the enumeration to the application with the given bundle identifier(s).
func WithIdentifiers(ids ...string) ApplicationOption {
	return func(options *applicationOptions) { options.identifiers = append(options.identifiers, ids...) }
}

// WithNames restricts the enumeration to applications whose name(s) match exactly.
func WithNames(names ...string) ApplicationOption {
	return func(options *applicationOptions) { options.names = append(options.names, names...) }
}

// ListApplications returns the applications installed on the remote device. The result is filtered according to the
// given options.
func (d *Device) ListApplications(ctx context.Context, opts ...ApplicationOption) ([]Application, error) {
	// Assemble options
	var config applicationOptions

	for _, opt := range opts {
		opt(&config)
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

	// Create query options if identifiers were given
	var options *C.FridaApplicationQueryOptions

	if len(config.identifiers) != 0 {
		options = C.frida_application_query_options_new()
		defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

		// Copy identifiers to C strings
		for _, identifier := range config.identifiers {
			identifierCopy := C.CString(identifier)
			defer C.free(unsafe.Pointer(identifierCopy))

			C.frida_application_query_options_select_identifier(options, identifierCopy)
		}
	}

	// Enumerate applications
	var gErr *C.GError

	list := C.frida_device_enumerate_applications_sync(d.handle, options, cancellable, &gErr)
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

		defer C.frida_unref(C.gpointer(unsafe.Pointer(app)))

		// Skip application if it does not match the requested names
		name := C.GoString(C.frida_application_get_name(app))

		if (len(config.names) != 0) && !slices.Contains(config.names, name) {
			continue
		}

		// Append application to list
		pid := uint(C.frida_application_get_pid(app))

		apps = append(apps, Application{
			Identifier: C.GoString(C.frida_application_get_identifier(app)),
			Name:       name,
			PID:        pid,
			Running:    pid != 0,
		})
	}

	return apps, nil
}

// FindApplicationByIdentifier returns the application with the given bundle identifier, or nil if no such application is
// installed on the remote device.
func (d *Device) FindApplicationByIdentifier(ctx context.Context, identifier string) (*Application, error) {
	// Validate input
	if identifier == "" {
		return nil, errors.New("no identifier given")
	}

	// Look up application by identifier
	apps, err := d.ListApplications(ctx, WithIdentifiers(identifier))
	if err != nil {
		return nil, err
	}

	// Early exit if no application matched
	if len(apps) == 0 {
		return nil, nil
	}

	return &apps[0], nil
}

// FindApplicationByName returns the first application with the given name, or nil if no such application is installed on
// the remote device.
func (d *Device) FindApplicationByName(ctx context.Context, name string) (*Application, error) {
	// Validate input
	if name == "" {
		return nil, errors.New("no name given")
	}

	// Look up application by name
	apps, err := d.ListApplications(ctx, WithNames(name))
	if err != nil {
		return nil, err
	}

	// Early exit if no application matched
	if len(apps) == 0 {
		return nil, nil
	}

	return &apps[0], nil
}

// FrontmostApplication returns the frontmost application on the remote device, or nil if there is none.
func (d *Device) FrontmostApplication(ctx context.Context) (*Application, error) {
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

	// Query frontmost application
	var gErr *C.GError

	handle := C.frida_device_get_frontmost_application_sync(d.handle, nil, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("get frontmost application: %w", err)
	}

	if handle == nil {
		// No frontmost application
		return nil, nil
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(handle)))

	// Copy application into a Go instance
	pid := uint(C.frida_application_get_pid(handle))

	return &Application{
		Identifier: C.GoString(C.frida_application_get_identifier(handle)),
		Name:       C.GoString(C.frida_application_get_name(handle)),
		PID:        pid,
		Running:    pid != 0,
	}, nil
}
