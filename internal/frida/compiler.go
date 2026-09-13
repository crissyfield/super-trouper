package frida

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"unsafe"
)

/*
#include <stdlib.h>
#include <frida-core.h>
*/
import "C"

// Package identifies a package installed by Frida's package manager.
type Package struct {
	Name    string
	Version string
}

// InstallOption configures a package installation.
type InstallOption func(*installOptions)

// installOptions holds the options for a Manager.InstallPackages call.
type installOptions struct {
	specs []string // Package specs to install.
}

// WithInstallSpec adds a package spec to install.
func WithInstallSpec(spec string) InstallOption {
	return func(options *installOptions) { options.specs = append(options.specs, spec) }
}

// InstallPackages installs package specs into the given Frida project.
func (m *Manager) InstallPackages(ctx context.Context, projectRoot string, opts ...InstallOption) ([]Package, error) {
	// Validate input
	if projectRoot == "" {
		return nil, errors.New("project root required")
	}

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

	// Serialize builds
	m.buildMu.Lock()
	defer m.buildMu.Unlock()

	m.mu.Lock()
	closed := m.closed
	packages := m.packages
	m.mu.Unlock()

	if closed {
		return nil, errManagerClosed
	}

	// Create installation options
	options := C.frida_package_install_options_new()
	defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

	cProjectRoot := C.CString(projectRoot)
	defer C.free(unsafe.Pointer(cProjectRoot))

	C.frida_package_install_options_set_project_root(options, cProjectRoot)
	C.frida_package_install_options_set_role(options, C.FRIDA_PACKAGE_ROLE_RUNTIME)

	for _, spec := range specs {
		cspec := C.CString(spec)
		C.frida_package_install_options_add_spec(options, cspec)
		C.free(unsafe.Pointer(cspec))
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Install packages
	var gErr *C.GError

	result := C.frida_package_manager_install_sync(
		packages,
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

// Compile bundles the entrypoint in the given Frida project into an IIFE script.
func (m *Manager) Compile(ctx context.Context, path string, entrypoint string) (string, error) {
	// Validate input
	if path == "" {
		return "", errors.New("project root required")
	}

	if entrypoint == "" {
		return "", errors.New("entrypoint required")
	}

	// Serialize builds and protect native resources from shutdown.
	m.buildMu.Lock()
	defer m.buildMu.Unlock()

	m.mu.Lock()
	closed := m.closed
	compiler := m.compiler
	m.mu.Unlock()

	if closed {
		return "", errManagerClosed
	}

	// Assemble options
	options := C.frida_build_options_new()
	if options == nil {
		return "", errors.New("create build options")
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

	cProjectRoot := C.CString(path)
	defer C.free(unsafe.Pointer(cProjectRoot))

	compilerOptions := (*C.FridaCompilerOptions)(unsafe.Pointer(options))
	C.frida_compiler_options_set_project_root(compilerOptions, cProjectRoot)
	C.frida_compiler_options_set_output_format(compilerOptions, C.FRIDA_OUTPUT_FORMAT_UNESCAPED)
	C.frida_compiler_options_set_bundle_format(compilerOptions, C.FRIDA_BUNDLE_FORMAT_IIFE)
	C.frida_compiler_options_set_type_check(compilerOptions, C.FRIDA_TYPE_CHECK_MODE_NONE)
	C.frida_compiler_options_set_source_maps(compilerOptions, C.FRIDA_SOURCE_MAPS_OMITTED)
	C.frida_compiler_options_set_compression(compilerOptions, C.FRIDA_JS_COMPRESSION_NONE)
	C.frida_compiler_options_set_platform(compilerOptions, C.FRIDA_JS_PLATFORM_GUM)

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Compile entrypoint
	var gErr *C.GError

	centrypoint := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(centrypoint))

	bundle := C.frida_compiler_build_sync(
		compiler,
		centrypoint,
		options,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return "", fmt.Errorf("compile script: %w", err)
	}

	if bundle == nil {
		return "", errors.New("compile script: empty")
	}

	defer C.g_free(C.gpointer(unsafe.Pointer(bundle)))

	return C.GoString(bundle), nil
}
