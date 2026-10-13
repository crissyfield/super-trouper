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
	"sync"
	"unsafe"
)

// errPatternCompilerClosed indicates that the pattern compiler is already closed.
var errPatternCompilerClosed = errors.New("pattern compiler already closed")

// PatternCompiler compiles Frida Pattern sources and decodes byte snapshots against them.
type PatternCompiler struct {
	mu          sync.Mutex              // Guards native compiler operations and state.
	workspaceMu *sync.RWMutex           // Shared workspace lock guarding package project access.
	closed      bool                    // Whether native resources were released.
	handle      *C.FridaPatternCompiler // Native Frida pattern compiler.
}

// newPatternCompiler creates a native Pattern compiler.
func newPatternCompiler(workspaceMu *sync.RWMutex) (*PatternCompiler, error) {
	// Create pattern compiler
	handle := C.frida_pattern_compiler_new()
	if handle == nil {
		return nil, errors.New("failed to create pattern compiler")
	}

	// Return PatternCompiler instance
	return &PatternCompiler{workspaceMu: workspaceMu, handle: handle}, nil
}

// close releases native Pattern compiler resources.
func (c *PatternCompiler) close() {
	// Synchronize access
	c.mu.Lock()
	defer c.mu.Unlock()

	// Early exit if already closed
	if c.closed {
		return
	}

	c.closed = true

	// Clean up
	C.frida_unref(C.gpointer(unsafe.Pointer(c.handle)))
	c.handle = nil
}

// PatternCompileOption configures a Pattern compile.
type PatternCompileOption func(*patternCompileOptions)

// patternCompileOptions holds the options for a PatternCompiler.Compile call.
type patternCompileOptions struct {
	projectRoot string // Project root used to resolve imports, empty for Frida's inferred default.
	platform    string // Target Process.platform value, empty to omit.
	arch        string // Target Process.arch value, empty to omit.
}

// WithPatternCompileProjectRoot sets the project root used to resolve imports.
func WithPatternCompileProjectRoot(path string) PatternCompileOption {
	return func(options *patternCompileOptions) { options.projectRoot = path }
}

// WithPatternCompilePlatform sets the target Process.platform value.
func WithPatternCompilePlatform(platform string) PatternCompileOption {
	return func(options *patternCompileOptions) { options.platform = platform }
}

// WithPatternCompileArch sets the target Process.arch value.
func WithPatternCompileArch(arch string) PatternCompileOption {
	return func(options *patternCompileOptions) { options.arch = arch }
}

// Compile compiles a Pattern entrypoint for a target platform and architecture.
func (c *PatternCompiler) Compile(ctx context.Context, entrypoint string, opts ...PatternCompileOption) (*PatternModule, error) {
	// Validate input
	if entrypoint == "" {
		return nil, errors.New("pattern entrypoint required")
	}

	// Synchronize access
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if pattern compiler is already closed
	if c.closed {
		return nil, errPatternCompilerClosed
	}

	// Synchronize project access
	c.workspaceMu.RLock()
	defer c.workspaceMu.RUnlock()

	// Assemble compile options
	var options *C.FridaPatternCompileOptions
	var config patternCompileOptions

	for _, opt := range opts {
		opt(&config)
	}

	if (config.projectRoot != "") || (config.platform != "") || (config.arch != "") {
		// Create compile options
		options = C.frida_pattern_compile_options_new()
		if options == nil {
			return nil, errors.New("create pattern compile options")
		}

		defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

		// Set project root
		if config.projectRoot != "" {
			cProjectRoot := C.CString(config.projectRoot)
			defer C.free(unsafe.Pointer(cProjectRoot))

			C.frida_pattern_compile_options_set_project_root(options, cProjectRoot)
		}

		// Set platform
		if config.platform != "" {
			cPlatform := C.CString(config.platform)
			defer C.free(unsafe.Pointer(cPlatform))

			C.frida_pattern_compile_options_set_platform(options, cPlatform)
		}

		// Set architecture
		if config.arch != "" {
			cArch := C.CString(config.arch)
			defer C.free(unsafe.Pointer(cArch))

			C.frida_pattern_compile_options_set_arch(options, cArch)
		}
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Compile entrypoint
	var gErr *C.GError

	cEntrypoint := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(cEntrypoint))

	handle := C.frida_pattern_compiler_compile_sync(
		c.handle,
		cEntrypoint,
		options,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("compile pattern: %w", err)
	}
	if handle == nil {
		return nil, errors.New("compile pattern: empty")
	}

	// Create module instance
	return newPatternModule(handle), nil
}
