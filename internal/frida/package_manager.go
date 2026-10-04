package frida

/*
#include <stdlib.h>
#include <frida-core.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

// errPackageManagerClosed indicates that the package manager is already closed.
var errPackageManagerClosed = errors.New("package manager already closed")

// PackageManager installs packages using Frida's package manager.
type PackageManager struct {
	mu        sync.Mutex             // Guards package manager state.
	projectMu sync.RWMutex           // Guards all package project access.
	closed    bool                   // Whether native resources were released.
	logger    *slog.Logger           // Logger for library events.
	handle    *C.FridaPackageManager // Native Frida package manager.
}

// Package identifies a package installed by Frida's package manager.
type Package struct {
	Name    string // Package name.
	Version string // Package version or version constraint.
}

// projectOptions holds the options for project functions, like InstallPackages and ListPackages.
type projectOptions struct {
	projectRoot string // Project root, empty for the default workspace root.
}

// ProjectOption allows to apply project options.
type ProjectOption interface {
	applyProject(*projectOptions)
}

// installOptions holds the options for InstallPackages.
type installOptions struct {
	projectRoot string    // Project root, empty for the default workspace root.
	packages    []Package // Packages to install.
}

// InstallOption allows to apply install options.
type InstallOption interface {
	applyInstall(*installOptions)
}

// ProjectRootOption sets the project root for package operations.
type ProjectRootOption string

// WithProjectRoot sets the project directory used by a package operation.
func WithProjectRoot(path string) ProjectRootOption {
	return ProjectRootOption(path)
}

// applyProject applies a project root option to a package operation.
func (o ProjectRootOption) applyProject(options *projectOptions) {
	options.projectRoot = string(o)
}

// applyInstall applies a project root option to a package installation.
func (o ProjectRootOption) applyInstall(options *installOptions) {
	options.projectRoot = string(o)
}

// InstallPackageOption identifies a package to install.
type InstallPackageOption Package

// WithInstallPackageName adds a package by name only to install.
func WithInstallPackageName(name string) InstallOption {
	return InstallPackageOption{Name: name}
}

// WithInstallPackageWithNameAndVersion adds a package with a version to install.
func WithInstallPackageWithNameAndVersion(name string, version string) InstallOption {
	return InstallPackageOption{Name: name, Version: version}
}

// applyInstall adds a package to an installation.
func (o InstallPackageOption) applyInstall(options *installOptions) {
	options.packages = append(options.packages, Package(o))
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

// resolvePackageProjectRoot resolves and creates a package project root.
func resolvePackageProjectRoot(root string) (string, error) {
	// Use default project root
	if root == "" {
		// Resolve cache directory
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("resolve user cache directory: %w", err)
		}

		root = filepath.Join(cacheDir, "super-trouper", "frida", Version())
	}

	// Create project root
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create project root [root=%s]: %w", root, err)
	}

	return root, nil
}

// InstallPackages installs packages into a Frida project.
func (p *PackageManager) InstallPackages(ctx context.Context, opts ...InstallOption) error {
	// Assemble options
	var config installOptions

	for _, opt := range opts {
		opt.applyInstall(&config)
	}

	// Validate and assemble package specs
	specs := make([]string, 0, len(config.packages))

	for _, packageSpec := range config.packages {
		// Validate
		if strings.TrimSpace(packageSpec.Name) == "" {
			return errors.New("package name required")
		}

		if (packageSpec.Version != "") && (strings.TrimSpace(packageSpec.Version) == "") {
			return errors.New("package version must not be whitespace")
		}

		// Assemble npm spec
		spec := packageSpec.Name
		if packageSpec.Version != "" {
			spec += "@" + packageSpec.Version
		}

		// Append
		specs = append(specs, spec)
	}

	// Skip empty installs
	if len(specs) == 0 {
		return nil
	}

	// Resolve project root
	root, err := resolvePackageProjectRoot(config.projectRoot)
	if err != nil {
		return fmt.Errorf("resolve project root: %w", err)
	}

	// Synchronize project access
	p.projectMu.Lock()
	defer p.projectMu.Unlock()

	// Synchronize access
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if package manager is already closed
	if p.closed {
		return errPackageManagerClosed
	}

	// Create installation options
	options := C.frida_package_install_options_new()
	if options == nil {
		return errors.New("create package install options")
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

	C.frida_package_install_options_set_role(options, C.FRIDA_PACKAGE_ROLE_RUNTIME)

	// Set project root
	cProjectRoot := C.CString(root)
	defer C.free(unsafe.Pointer(cProjectRoot))

	C.frida_package_install_options_set_project_root(options, cProjectRoot)

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
		return fmt.Errorf("install packages: %w", err)
	}

	if result == nil {
		return errors.New("install packages: empty")
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(result)))

	return nil
}

// packageManifest contains the direct runtime dependencies of a package project.
type packageManifest struct {
	Dependencies map[string]string `json:"dependencies"`
}

// packageLockfile contains the resolved package versions recorded by npm.
type packageLockfile struct {
	Packages     map[string]packageLockEntry `json:"packages"`
	Dependencies map[string]packageLockEntry `json:"dependencies"`
}

// packageLockEntry contains the installed version of a package.
type packageLockEntry struct {
	Version string `json:"version"`
}

// ListPackages lists the direct packages installed in a Frida project.
func (p *PackageManager) ListPackages(opts ...ProjectOption) ([]Package, error) {
	// Assemble options
	var config projectOptions

	for _, opt := range opts {
		opt.applyProject(&config)
	}

	// Resolve project root
	root, err := resolvePackageProjectRoot(config.projectRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}

	// Synchronize project access
	p.projectMu.RLock()
	defer p.projectMu.RUnlock()

	// Read package manifest
	manifestData, err := os.ReadFile(filepath.Join(root, "package.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("read package manifest [root=%s]: %w", root, err)
	}

	// Decode package manifest
	var manifest packageManifest

	err = json.Unmarshal(manifestData, &manifest)
	if err != nil {
		return nil, fmt.Errorf("decode package manifest [root=%s]: %w", root, err)
	}

	// Read package lockfile (if present)
	var lockfile packageLockfile

	lockData, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if (err != nil) && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read package lockfile [root=%s]: %w", root, err)
	}

	if err == nil {
		// Decode package lockfile
		err := json.Unmarshal(lockData, &lockfile)
		if err != nil {
			return nil, fmt.Errorf("decode package lockfile [root=%s]: %w", root, err)
		}
	}

	// Collect direct package entries
	packages := make([]Package, 0, len(manifest.Dependencies))

	for name, spec := range manifest.Dependencies {
		// Resolve version
		version := spec

		if entry, ok := lockfile.Packages["node_modules/"+name]; ok && (entry.Version != "") {
			// Use resolved version from packages
			version = entry.Version
		} else if entry, ok := lockfile.Dependencies[name]; ok && (entry.Version != "") {
			// Use resolved version from dependencies
			version = entry.Version
		}

		// Append
		packages = append(packages, Package{
			Name:    name,
			Version: version,
		})
	}

	// Sort packages
	sort.Slice(packages, func(i int, j int) bool {
		return packages[i].Name < packages[j].Name
	})

	return packages, nil
}
