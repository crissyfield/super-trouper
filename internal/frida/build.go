package frida

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PackageInfo describes an npm package to install and expose as a global in a built bundle.
type PackageInfo struct {
	Name   string // Name of the npm package to install.
	Export string // Name of the globalThis export exposed to script source.
}

// BuildOption configures a script build.
type BuildOption func(*buildOptions)

// buildOptions holds the options for a Manager.BuildScript call.
type buildOptions struct {
	projectRoot string // Project root, empty for the default workspace root.
}

// WithBuildProjectRoot sets the project root to build in. When empty, the default workspace root is used.
func WithBuildProjectRoot(path string) BuildOption {
	return func(options *buildOptions) { options.projectRoot = path }
}

// BuildScript installs the selected packages, if any, and compiles the source into a self-contained IIFE bundle.
func (m *Manager) BuildScript(ctx context.Context, source string, packages []PackageInfo, opts ...BuildOption) (string, error) {
	// Assemble options
	var config buildOptions

	for _, opt := range opts {
		opt(&config)
	}

	// Resolve workspace folder
	root, err := resolvePackageProjectRoot(config.projectRoot)
	if err != nil {
		return "", fmt.Errorf("resolve project root: %w", err)
	}

	// Get package manager
	pm, err := m.PackageManager()
	if err != nil {
		return "", fmt.Errorf("get package manager: %w", err)
	}

	if len(packages) > 0 {
		// Assemble installation options
		installOpts := make([]InstallOption, 0, len(packages)+1)
		installOpts = append(installOpts, WithProjectRoot(root))

		for _, info := range packages {
			installOpts = append(installOpts, WithInstallPackageName(info.Name))
		}

		// Install packages
		err = pm.InstallPackages(ctx, installOpts...)
		if err != nil {
			return "", fmt.Errorf("install packages: %w", err)
		}
	}

	// Create build directory
	dir, err := os.MkdirTemp(root, "build-*")
	if err != nil {
		return "", fmt.Errorf("create build directory: %w", err)
	}

	defer os.RemoveAll(dir) //nolint

	// Write supplied source to temporary `source.ts` file
	sourcePath := filepath.Join(dir, "source.ts")

	err = os.WriteFile(
		sourcePath,
		[]byte(source),
		0o600,
	)

	if err != nil {
		return "", fmt.Errorf("write source: %w", err)
	}

	// Write package imports to temporary `imports.ts` file
	var imports strings.Builder

	for _, pkg := range packages {
		fmt.Fprintf(&imports, "import %s from %q;\n", pkg.Export, pkg.Name)
		fmt.Fprintf(&imports, "globalThis.%s = %s;\n", pkg.Export, pkg.Export)
	}

	importsPath := filepath.Join(dir, "imports.ts")

	err = os.WriteFile(
		importsPath,
		[]byte(imports.String()),
		0o600,
	)

	if err != nil {
		return "", fmt.Errorf("write imports: %w", err)
	}

	// Write entrypoint module into temporary `entry.ts` file
	entryPath := filepath.Join(dir, "entry.ts")

	err = os.WriteFile(
		entryPath,
		[]byte(`
			import "./imports.ts";
			import "./source.ts";
		`),
		0o600,
	)

	if err != nil {
		return "", fmt.Errorf("write entrypoint: %w", err)
	}

	// Get compiler
	compiler, err := m.Compiler()
	if err != nil {
		return "", fmt.Errorf("get compiler: %w", err)
	}

	// Synchronize project access
	pm.projectMu.RLock()
	defer pm.projectMu.RUnlock()

	// Compile bundle
	bundle, err := compiler.Compile(
		ctx,
		entryPath,
		WithCompileProjectRoot(root),
	)

	if err != nil {
		return "", fmt.Errorf("compile bundle: %w", err)
	}

	return bundle, nil
}
