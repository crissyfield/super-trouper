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
	"sync"
	"unsafe"
)

// errCompilerClosed indicates that the compiler is already closed.
var errCompilerClosed = errors.New("compiler already closed")

// Compiler bundles scripts using Frida's compiler.
type Compiler struct {
	mu     sync.Mutex       // Guards compiler state.
	closed bool             // Whether native resources were released.
	logger *slog.Logger     // Logger for library events.
	handle *C.FridaCompiler // Native Frida compiler.
}

// CompileOption configures a compiler build.
type CompileOption func(*compileOptions)

// compileOptions holds the options for a Compiler.Compile call.
type compileOptions struct {
	projectRoot string // Project root, empty for Frida's inferred default.
}

// WithCompilerProjectRoot sets the project root for a buikd. Current directory is used if not set.
// absolute, or the current working directory otherwise.
func WithCompileProjectRoot(path string) CompileOption {
	return func(options *compileOptions) { options.projectRoot = path }
}

// newCompiler creates a compiler from the given Frida device manager.
func newCompiler(manager *C.FridaDeviceManager, logger *slog.Logger) (*Compiler, error) {
	// Create compiler
	handle := C.frida_compiler_new(manager)
	if handle == nil {
		return nil, errors.New("create compiler")
	}

	// Return Compiler instance
	return &Compiler{logger: logger, handle: handle}, nil
}

// close releases native compiler resources.
func (c *Compiler) close() {
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

// Compile bundles an entrypoint into an IIFE script.
func (c *Compiler) Compile(ctx context.Context, entrypoint string, opts ...CompileOption) (string, error) {
	// Assemble options
	var config compileOptions

	for _, opt := range opts {
		opt(&config)
	}

	// Validate input
	if entrypoint == "" {
		return "", errors.New("entrypoint required")
	}

	// Synchronize access
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if compiler is already closed
	if c.closed {
		return "", errCompilerClosed
	}

	// Assemble options
	options := C.frida_build_options_new()
	if options == nil {
		return "", errors.New("create build options")
	}

	defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

	compilerOptions := (*C.FridaCompilerOptions)(unsafe.Pointer(options))
	C.frida_compiler_options_set_output_format(compilerOptions, C.FRIDA_OUTPUT_FORMAT_UNESCAPED)
	C.frida_compiler_options_set_bundle_format(compilerOptions, C.FRIDA_BUNDLE_FORMAT_IIFE)
	C.frida_compiler_options_set_type_check(compilerOptions, C.FRIDA_TYPE_CHECK_MODE_NONE)
	C.frida_compiler_options_set_source_maps(compilerOptions, C.FRIDA_SOURCE_MAPS_OMITTED)
	C.frida_compiler_options_set_compression(compilerOptions, C.FRIDA_JS_COMPRESSION_NONE)
	C.frida_compiler_options_set_platform(compilerOptions, C.FRIDA_JS_PLATFORM_GUM)

	if config.projectRoot != "" {
		// Set project root
		cProjectRoot := C.CString(config.projectRoot)
		defer C.free(unsafe.Pointer(cProjectRoot))

		C.frida_compiler_options_set_project_root(compilerOptions, cProjectRoot)
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Compile entrypoint
	var gErr *C.GError

	cEntrypoint := C.CString(entrypoint)
	defer C.free(unsafe.Pointer(cEntrypoint))

	bundle := C.frida_compiler_build_sync(
		c.handle,
		cEntrypoint,
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
