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

// CreateScript creates a script in the session from the given source and loads it.
func (s *Session) CreateScript(ctx context.Context, source string) (*Script, error) {
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

	// Create script
	var gErr *C.GError

	cSource := C.CString(source)
	defer C.free(unsafe.Pointer(cSource))

	handle := C.frida_session_create_script_sync(
		s.handle,
		cSource,
		nil,
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
	script, err := newScript(s, handle, cancellable)
	if err != nil {
		C.frida_unref(C.gpointer(unsafe.Pointer(handle)))
		return nil, fmt.Errorf("create script: %w", err)
	}

	s.scripts[script] = struct{}{}

	return script, nil
}
