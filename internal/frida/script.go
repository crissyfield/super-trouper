package frida

/*
#include <stdint.h>
#include <stdlib.h>
#include <frida-core.h>

// The Go routine that should be called for each message.
extern void goFridaScriptMessage(const gchar * message, gconstpointer data, gsize data_size, uintptr_t handle);

// Is called from C and forwards the message to the proper Script instance.
static void on_script_message(FridaScript * script, const gchar * message, GBytes * data, gpointer user_data) {
  (void) script;

  gconstpointer data_ptr = NULL;
  gsize data_size = 0;

  if (data != NULL) {
    data_ptr = g_bytes_get_data(data, &data_size);
  }

  goFridaScriptMessage(message, data_ptr, data_size, (uintptr_t) user_data);
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
	"sync/atomic"
	"unsafe"
)

// Number of buffered script messages before new messages are dropped.
const scriptMessagesBuffer = 256

// errScriptClosed indicates that the script was closed.
var errScriptClosed = errors.New("script already closed")

// ScriptMessage is a message sent by a script, optionally carrying a binary payload.
type ScriptMessage struct {
	JSON string // Raw JSON message.
	Data []byte // Binary payload, nil if the message carries no data.
}

// Script is a script loaded into a session attached to a process on a Frida device.
type Script struct {
	mu         sync.Mutex         // Guards script state.
	closed     atomic.Bool        // Whether resources were released.
	loaded     bool               // Whether the script is loaded into its target process.
	session    *Session           // Owning session.
	logger     *slog.Logger       // Logger for library events.
	handle     *C.FridaScript     // Native Frida script handle.
	messages   chan ScriptMessage // Incoming script messages.
	usrdata    cgo.Handle         // Keeps the script reachable from C.
	msghandler uintptr            // Native script message handler.
}

// newScript creates a script instance for a session and connects its message handler. The script is not loaded;
// call Load to load it.
func newScript(session *Session, handle *C.FridaScript) (*Script, error) {
	// Create script instance
	script := &Script{
		session:  session,
		logger:   session.logger,
		handle:   handle,
		messages: make(chan ScriptMessage, scriptMessagesBuffer),
	}

	// Connect message handler
	script.usrdata = cgo.NewHandle(script)

	script.msghandler = uintptr(C.connect_script_message(handle, C.uintptr_t(script.usrdata)))
	if script.msghandler == 0 {
		script.usrdata.Delete()
		return nil, fmt.Errorf("failed to connect message handler [pid=%d]", session.pid)
	}

	return script, nil
}

// Close unloads the script if loaded and releases resources.
func (s *Script) Close(ctx context.Context) error {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Early exit if already closed, close otherwise
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Unload script
	var closeErr error

	if s.loaded {
		var gErr *C.GError

		C.frida_script_unload_sync(s.handle, cancellable, &gErr)
		if err := consumeGError(gErr); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("unload script [pid=%d]: %w", s.session.pid, err))
		}

		s.loaded = false
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

// Load loads the script into its target process. Loading an already loaded script is a no-op.
func (s *Script) Load(ctx context.Context) error {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Early exit if already closed
	if s.closed.Load() {
		return errScriptClosed
	}

	// Early exit if already loaded
	if s.loaded {
		return nil
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Load script
	var gErr *C.GError

	C.frida_script_load_sync(s.handle, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return fmt.Errorf("load script [pid=%d]: %w", s.session.pid, err)
	}

	s.loaded = true

	return nil
}

// Unload unloads the script from its target process. The script stays registered with its session, and its
// message stream remains available for draining. Unloading an already unloaded script is a no-op.
func (s *Script) Unload(ctx context.Context) error {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Early exit if already closed
	if s.closed.Load() {
		return errScriptClosed
	}

	// Early exit if not loaded
	if !s.loaded {
		return nil
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Unload script
	var gErr *C.GError

	C.frida_script_unload_sync(s.handle, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return fmt.Errorf("unload script [pid=%d]: %w", s.session.pid, err)
	}

	s.loaded = false

	return nil
}

// Post sends the given JSON message to the script, with an optional binary payload.
func (s *Script) Post(json string, data []byte) error {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Early exit if already closed
	if s.closed.Load() {
		return errScriptClosed
	}

	// Encode message
	cJSON := C.CString(json)
	defer C.free(unsafe.Pointer(cJSON))

	// Wrap binary payload
	var gData *C.GBytes

	if len(data) != 0 {
		gData = C.g_bytes_new(C.gconstpointer(unsafe.Pointer(&data[0])), C.gsize(len(data)))
		defer C.g_bytes_unref(gData)
	}

	C.frida_script_post(s.handle, cJSON, gData)

	return nil
}

// Messages returns the stream of messages sent by the script.
func (s *Script) Messages() <-chan ScriptMessage {
	return s.messages
}

// handleMessage delivers a script message to the message stream, or records a drop when the stream is full. It is
// called from the Frida event loop thread and must not block.
func (s *Script) handleMessage(json string, data []byte) {
	// Early exit if already closed
	if s.closed.Load() {
		return
	}

	// Non-blocking send
	select {
	case s.messages <- ScriptMessage{JSON: json, Data: data}:
		// Message delivered

	default:
		// Warn about dropped messages
		s.logger.Warn("Dropped script messages")
	}
}
