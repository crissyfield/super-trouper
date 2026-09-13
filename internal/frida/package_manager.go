package frida

/*
#include <stdlib.h>
#include <frida-core.h>
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"unsafe"
)

// errPackageManagerClosed indicates that the package manager is already closed.
var errPackageManagerClosed = errors.New("package manager already closed")

// PackageManager installs packages using Frida's package manager.
type PackageManager struct {
	mu     sync.Mutex             // Guards package manager state.
	closed bool                   // Whether native resources were released.
	logger *slog.Logger           // Logger for library events.
	handle *C.FridaPackageManager // Native Frida package manager.
}

// Package identifies a package installed by Frida's package manager.
type Package struct {
	Name    string // Package name.
	Version string // Installed package version.
}

// InstallOption configures a package installation.
type InstallOption func(*installOptions)

// installOptions holds the options for a PackageManager.InstallPackages call.
type installOptions struct {
	projectRoot string   // Project root, empty for Frida's current-directory default.
	specs       []string // Package specs to install.
}

// WithInstallProjectRoot sets the project directory to install into. Current directory is used if not set.
func WithInstallProjectRoot(path string) InstallOption {
	return func(options *installOptions) { options.projectRoot = path }
}

// WithInstallSpec adds a package spec to install.
func WithInstallSpec(spec string) InstallOption {
	return func(options *installOptions) { options.specs = append(options.specs, spec) }
}

// newPackageManager creates a Frida package manager.
func newPackageManager(logger *slog.Logger) (*PackageManager, error) {
	// Create package manager
	handle := C.frida_package_manager_new()
	if handle == nil {
		return nil, errors.New("create package manager")
	}

	// Return PackageManager instance
	return &PackageManager{logger: logger, handle: handle}, nil
}

// close releases native package manager resources.
func (p *PackageManager) close() {
	// Synchronize access
	p.mu.Lock()
	defer p.mu.Unlock()

	// Early exit if already closed
	if p.closed {
		return
	}

	p.closed = true

	// Clean up
	C.frida_unref(C.gpointer(unsafe.Pointer(p.handle)))
	p.handle = nil
}

// InstallPackages installs package specs into a Frida project.
func (p *PackageManager) InstallPackages(ctx context.Context, opts ...InstallOption) ([]Package, error) {
	// Assemble options
	var config installOptions

	for _, opt := range opts {
		opt(&config)
	}

	specs := config.specs
	if len(specs) == 0 {
		return nil, nil
	}

	if slices.Contains(specs, "") {
		return nil, errors.New("package spec required")
	}

	// Synchronize access
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if package manager is already closed
	if p.closed {
		return nil, errPackageManagerClosed
	}

	// Create installation options
	options := C.frida_package_install_options_new()
	if options == nil {
		return nil, errors.New("create package install options")
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

	C.frida_package_install_options_set_role(options, C.FRIDA_PACKAGE_ROLE_RUNTIME)

	if config.projectRoot != "" {
		// Set project root
		cProjectRoot := C.CString(config.projectRoot)
		defer C.free(unsafe.Pointer(cProjectRoot))

		C.frida_package_install_options_set_project_root(options, cProjectRoot)
	}

	for _, spec := range specs {
		// Add package spec
		cSpec := C.CString(spec)
		defer C.free(unsafe.Pointer(cSpec))

		C.frida_package_install_options_add_spec(options, cSpec)
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Install packages
	var gErr *C.GError

	result := C.frida_package_manager_install_sync(
		p.handle,
		options,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("install packages: %w", err)
	}

	if result == nil {
		return nil, errors.New("install packages: empty")
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(result)))

	// Collect packages changed by this installation.
	list := C.frida_package_install_result_get_packages(result)
	if list == nil {
		return nil, nil
	}

	count := int(C.frida_package_list_size(list))
	installed := make([]Package, 0, count)

	for i := range count {
		// Get package from list
		item := C.frida_package_list_get(list, C.gint(i))
		if item == nil {
			continue
		}

		// Append package to list
		installed = append(installed, Package{
			Name:    C.GoString(C.frida_package_get_name(item)),
			Version: C.GoString(C.frida_package_get_version(item)),
		})
	}

	return installed, nil
}
