package frida

/*
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

// errSessionClosed indicates that the session was closed.
var errSessionClosed = errors.New("session already closed")

// Session is a session attached to a process on a Frida device.
type Session struct {
	mu      sync.Mutex           // Guards session state.
	closed  bool                 // Whether resources were released.
	logger  *slog.Logger         // Logger for library events.
	device  *Device              // Parent Frida device.
	handle  *C.FridaSession      // Native Frida session handle.
	pid     uint                 // Attached process PID.
	scripts map[*Script]struct{} // Loaded scripts.
}

// newSession wraps a native Frida session.
func newSession(device *Device, handle *C.FridaSession, pid uint) *Session {
	// Return Session instance
	return &Session{
		logger:  device.logger,
		device:  device,
		handle:  handle,
		pid:     pid,
		scripts: make(map[*Script]struct{}),
	}
}

// Close detaches the session from its process and releases resources.
func (s *Session) Close(ctx context.Context) error {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Early exit if already closed
	if s.closed {
		return nil
	}

	s.closed = true

	// Report active scripts instead of unloading them
	var closeErr error

	if len(s.scripts) != 0 {
		s.logger.Error("Active scripts remain", slog.Int("count", len(s.scripts)))
		closeErr = fmt.Errorf("active scripts remain [count=%d]", len(s.scripts))
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Detach session
	var gErr *C.GError

	C.frida_session_detach_sync(s.handle, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("detach session: %w", err))
	}

	// Clean up
	C.frida_unref(C.gpointer(unsafe.Pointer(s.handle)))
	s.handle = nil

	s.device.releaseSession(s)
	s.device = nil

	return closeErr
}

// releaseScript removes a script from the session's active scripts map.
func (s *Session) releaseScript(script *Script) {
	// Synchronize delete
	s.mu.Lock()
	delete(s.scripts, script)
	s.mu.Unlock()
}

// PID returns the PID of the attached process.
func (s *Session) PID() uint {
	return s.pid
}

// ScriptOption configures a single aspect of a Session.CreateScript call.
type ScriptOption func(*scriptOptions)

// scriptOptions holds the options for a Session.CreateScript call.
type scriptOptions struct {
	name              string            // Script name.
	runtime           ScriptRuntime     // JavaScript runtime, empty for Frida's default runtime.
	snapshot          []byte            // QuickJS snapshot to seed the script with.
	snapshotTransport SnapshotTransport // How the snapshot is delivered.
}

// WithScriptName sets the script name.
func WithScriptName(name string) ScriptOption {
	return func(options *scriptOptions) { options.name = name }
}

// WithScriptRuntime sets the JavaScript runtime used by the script.
func WithScriptRuntime(runtime ScriptRuntime) ScriptOption {
	return func(options *scriptOptions) { options.runtime = runtime }
}

// WithScriptSnapshot seeds the script with the given QuickJS snapshot.
func WithScriptSnapshot(snapshot []byte) ScriptOption {
	return func(options *scriptOptions) { options.snapshot = snapshot }
}

// WithScriptSnapshotTransport sets how the script snapshot is delivered to the target process. Requires
// WithScriptSnapshot.
func WithScriptSnapshotTransport(transport SnapshotTransport) ScriptOption {
	return func(options *scriptOptions) { options.snapshotTransport = transport }
}

// CreateScript creates a script in the session from the given source. The script is not loaded until Script.Load
// is called.
func (s *Session) CreateScript(ctx context.Context, source string, opts ...ScriptOption) (*Script, error) {
	// Validate input
	if source == "" {
		return nil, errors.New("no script source given")
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Early exit if session is already closed
	if s.closed {
		return nil, errSessionClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Assemble script options
	var options *C.FridaScriptOptions
	var config scriptOptions

	for _, opt := range opts {
		opt(&config)
	}

	if (config.name != "") || (config.runtime != "") || (len(config.snapshot) > 0) || (config.snapshotTransport != "") {
		// Create script options
		options = C.frida_script_options_new()
		defer C.g_object_unref(C.gpointer(unsafe.Pointer(options)))

		// Set name
		if config.name != "" {
			cname := C.CString(config.name)
			defer C.free(unsafe.Pointer(cname))

			C.frida_script_options_set_name(options, cname)
		}

		// Set runtime
		if config.runtime != "" {
			cruntime, ok := scriptRuntimeToFrida(config.runtime)
			if !ok {
				return nil, fmt.Errorf("invalid script runtime [runtime=%q]", config.runtime)
			}

			C.frida_script_options_set_runtime(options, cruntime)
		}

		// Set snapshot
		if len(config.snapshot) != 0 {
			csnapshot := C.g_bytes_new(C.gconstpointer(unsafe.Pointer(&config.snapshot[0])), C.gsize(len(config.snapshot)))
			defer C.g_bytes_unref(csnapshot)

			C.frida_script_options_set_snapshot(options, csnapshot)
		}

		// Set snapshot transport
		if config.snapshotTransport != "" {
			ctransport, ok := snapshotTransportToFrida(config.snapshotTransport)
			if !ok {
				return nil, fmt.Errorf("invalid snapshot transport [transport=%q]", config.snapshotTransport)
			}

			C.frida_script_options_set_snapshot_transport(options, ctransport)
		}
	}

	// Create script
	var gErr *C.GError

	cSource := C.CString(source)
	defer C.free(unsafe.Pointer(cSource))

	handle := C.frida_session_create_script_sync(
		s.handle,
		cSource,
		options,
		cancellable,
		&gErr,
	)

	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("create script for process [pid=%d]: %w", s.pid, err)
	}

	if handle == nil {
		return nil, fmt.Errorf("create script for process [pid=%d]: empty", s.pid)
	}

	// Create script instance
	script, err := newScript(s, handle)
	if err != nil {
		C.frida_unref(C.gpointer(unsafe.Pointer(handle)))
		return nil, fmt.Errorf("create script: %w", err)
	}

	s.scripts[script] = struct{}{}

	return script, nil
}

// CreateAndLoadScript creates a script in the session from the given source and loads it.
func (s *Session) CreateAndLoadScript(ctx context.Context, source string, opts ...ScriptOption) (*Script, error) {
	// Create script
	script, err := s.CreateScript(ctx, source, opts...)
	if err != nil {
		return nil, fmt.Errorf("create script: %w", err)
	}

	// Load script
	if err := script.Load(ctx); err != nil {
		// Release the unusable script, preferring the load error
		_ = script.Close(ctx)
		return nil, fmt.Errorf("load script: %w", err)
	}

	return script, nil
}
