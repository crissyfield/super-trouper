package frida

/*
#include <stdint.h>
#include <stdlib.h>
#include <frida-core.h>

// The Go routine that should be called for each message.
extern void goFridaScriptMessage(const gchar * message, uintptr_t handle);

// Is called from C and forwards the message to the proper Script instance.
static void on_script_message(FridaScript * script, const gchar * message, GBytes * data, gpointer user_data) {
  (void) script;
  (void) data;
  goFridaScriptMessage(message, (uintptr_t) user_data);
}

// Connects the script message signal to the on_script_message callback.
static gulong connect_script_message(FridaScript * script, uintptr_t handle) {
  return g_signal_connect(script, "message", G_CALLBACK(on_script_message), (gpointer) handle);
}

// Disconnects the script message signal from the on_script_message callback.
static void disconnect_script_message(FridaScript * script, gulong handler) {
  g_signal_handler_disconnect(script, handler);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/cgo"
	"sync"
	"unsafe"
)

// Number of buffered script messages before new messages are dropped.
const scriptMessagesBuffer = 32

// Script is a script loaded into a session attached to a process on a Frida device.
type Script struct {
	mu         sync.Mutex     // Guards script state.
	closed     bool           // Whether resources were released.
	session    *Session       // Owning session.
	logger     *slog.Logger   // Logger for library events.
	handle     *C.FridaScript // Native Frida script handle.
	messages   chan string    // Incoming script messages.
	usrdata    cgo.Handle     // Keeps the script reachable from C.
	msghandler uintptr        // Native script message handler.
}

// newScript creates a script in a session, connects its message handler, and loads it.
func newScript(session *Session, handle *C.FridaScript, cancellable *C.GCancellable) (*Script, error) {
	// Create script instance
	script := &Script{
		session:  session,
		logger:   session.logger,
		handle:   handle,
		messages: make(chan string, scriptMessagesBuffer),
	}

	// Connect message handler
	script.usrdata = cgo.NewHandle(script)

	script.msghandler = uintptr(C.connect_script_message(handle, C.uintptr_t(script.usrdata)))
	if script.msghandler == 0 {
		script.usrdata.Delete()
		return nil, fmt.Errorf("failed to connect message handler [pid=%d]", session.pid)
	}

	// Load script
	var gErr *C.GError

	C.frida_script_load_sync(handle, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		C.disconnect_script_message(handle, C.gulong(script.msghandler))
		script.usrdata.Delete()
		return nil, fmt.Errorf("load script [pid=%d]: %w", session.pid, err)
	}

	return script, nil
}

// Close unloads the script and releases resources.
func (s *Script) Close(ctx context.Context) error {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Early exit if already closed
	if s.closed {
		return nil
	}

	s.closed = true

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Unload script
	var closeErr error
	var gErr *C.GError

	C.frida_script_unload_sync(s.handle, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("unload script: %w", err))
	}

	// Disconnect message handler
	C.disconnect_script_message(s.handle, C.gulong(s.msghandler))
	s.msghandler = 0

	// Clean up
	s.usrdata.Delete()
	s.usrdata = 0

	C.frida_unref(C.gpointer(unsafe.Pointer(s.handle)))
	s.handle = nil

	s.session.releaseScript(s)
	s.session = nil

	return closeErr
}

// Messages returns the stream of messages sent by the script.
func (s *Script) Messages() <-chan string {
	return s.messages
}
