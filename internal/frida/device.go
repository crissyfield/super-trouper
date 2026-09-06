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

// errDeviceClosed indicates that the device is already closed.
var errDeviceClosed = errors.New("device already closed")

// Device is a connection to a Frida device.
type Device struct {
	mu       sync.Mutex        // Guards device state.
	closed   bool              // Whether resources were released.
	logger   *slog.Logger      // Logger for library events.
	manager  *Manager          // Parent Frida manager.
	handle   *C.FridaDevice    // Native Frida device handle.
	id       string            // Frida device ID.
	name     string            // Human-readable device name.
	dtype    DeviceType        // Connection transport type.
	sessions map[uint]*Session // Attached process sessions keyed by PID.
}

// newDevice creates a device instance around a native Frida device handle.
func newDevice(manager *Manager, handle *C.FridaDevice) *Device {
	// Return Device instance
	return &Device{
		logger:   manager.logger,
		manager:  manager,
		handle:   handle,
		id:       C.GoString(C.frida_device_get_id(handle)),
		name:     C.GoString(C.frida_device_get_name(handle)),
		dtype:    deviceTypeFromFrida(C.frida_device_get_dtype(handle)),
		sessions: make(map[uint]*Session),
	}
}

// Close disconnects from the Frida device and releases resources.
func (d *Device) Close(ctx context.Context) error {
	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if already closed
	if d.closed {
		return nil
	}

	d.closed = true

	// Report active sessions instead of closing them
	var closeErr error

	if len(d.sessions) != 0 {
		d.logger.Error("Active sessions remain", slog.Int("count", len(d.sessions)))
		closeErr = fmt.Errorf("active sessions remain [count=%d]", len(d.sessions))
	}

	// Clean up
	C.frida_unref(C.gpointer(unsafe.Pointer(d.handle)))
	d.handle = nil

	d.manager.releaseDevice(d)
	d.manager = nil

	return closeErr
}

// releaseSession removes a session from the device's active sessions map.
func (d *Device) releaseSession(session *Session) {
	// Synchronize delete
	d.mu.Lock()
	delete(d.sessions, session.pid)
	d.mu.Unlock()
}

// ID returns the Frida device ID.
func (d *Device) ID() string {
	return d.id
}

// Name returns the human-readable device name.
func (d *Device) Name() string {
	return d.name
}

// Type returns the connection transport type.
func (d *Device) Type() DeviceType {
	return d.dtype
}

// Params returns the system parameters reported by the device, such as the operating system, platform, and access
// level.
func (d *Device) Params(ctx context.Context) (map[string]any, error) {
	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return nil, errDeviceClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Query system parameters
	var gErr *C.GError

	table := C.frida_device_query_system_parameters_sync(d.handle, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("query system parameters: %w", err)
	}

	if table == nil {
		// No parameters reported
		return nil, nil
	}

	defer C.g_hash_table_unref(table)

	// Copy parameters into a Go map
	params := make(map[string]any, int(C.g_hash_table_size(table)))

	var iter C.GHashTableIter
	var key, value C.gpointer

	C.g_hash_table_iter_init(&iter, table)
	for C.g_hash_table_iter_next(&iter, &key, &value) != 0 {
		key := C.GoString((*C.char)(unsafe.Pointer(key)))
		val := valueFromVariant((*C.GVariant)(unsafe.Pointer(value)))
		params[key] = val
	}

	return params, nil
}

// IsLost reports whether the connection to the device was lost. A closed device is always reported as lost.
func (d *Device) IsLost() bool {
	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return true
	}

	// Check device state
	return C.frida_device_is_lost(d.handle) != 0
}

// SessionOption configures a single aspect of a Device.Attach call.
type SessionOption func(*sessionOptions)

// sessionOptions holds the options for attaching to a process.
type sessionOptions struct {
	persistTimeout uint // Seconds a session survives a dropped connection, zero for Frida's default.
}

// WithSessionPersistTimeout sets how long, in seconds, the session persists on the target process after the connection
// drops, allowing the session to be resumed without losing instrumentation state. Zero disables persistence, which is
// Frida's default.
func WithSessionPersistTimeout(timeout uint) SessionOption {
	return func(options *sessionOptions) { options.persistTimeout = timeout }
}

// Attach attaches to the process with the given PID and returns the new session.
func (d *Device) Attach(ctx context.Context, pid uint, opts ...SessionOption) (*Session, error) {
	// Validate input
	if pid == 0 {
		return nil, errors.New("no pid given")
	}

	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return nil, errDeviceClosed
	}

	// Early exit if the process already has an attached session
	if d.sessions[pid] != nil {
		return nil, fmt.Errorf("already attached to process [pid=%d]", pid)
	}

	// Assemble session options
	var options *C.FridaSessionOptions
	var config sessionOptions

	for _, opt := range opts {
		opt(&config)
	}

	if config.persistTimeout != 0 {
		// Create session options
		options = C.frida_session_options_new()
		defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

		// Set persist timeout
		C.frida_session_options_set_persist_timeout(options, C.guint(config.persistTimeout))
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Attach to process
	var gErr *C.GError

	handle := C.frida_device_attach_sync(d.handle, C.guint(pid), options, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return nil, fmt.Errorf("attach to process [pid=%d]: %w", pid, err)
	}

	if handle == nil {
		return nil, fmt.Errorf("attach to process [pid=%d]: empty", pid)
	}

	// Create session instance
	session := newSession(d, handle, pid)
	d.sessions[pid] = session

	return session, nil
}

// SpawnOption configures a single aspect of a Device.Spawn call.
type SpawnOption func(*spawnOptions)

// spawnOptions holds the options for a Device.Spawn call.
type spawnOptions struct {
	argv []string          // Full argument vector, including the program.
	env  map[string]string // Environment variables added on top of the inherited environment.
	cwd  string            // Working directory.
}

// WithSpawnArgv replaces the program argument with the given argument vector, where the first element is the
// program to execute.
func WithSpawnArgv(argv []string) SpawnOption {
	return func(options *spawnOptions) { options.argv = argv }
}

// WithSpawnEnv adds the given environment variables on top of the inherited environment.
func WithSpawnEnv(env map[string]string) SpawnOption {
	return func(options *spawnOptions) { options.env = env }
}

// WithSpawnCwd sets the working directory for the spawned process.
func WithSpawnCwd(cwd string) SpawnOption {
	return func(options *spawnOptions) { options.cwd = cwd }
}

// Spawn spawns the program with the given name on the remote device in suspended state and returns the process ID. Use
// Resume to start execution of the spawned process.
func (d *Device) Spawn(ctx context.Context, name string, opts ...SpawnOption) (uint, error) {
	// Validate input
	if name == "" {
		return 0, errors.New("no program given")
	}

	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return 0, errDeviceClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Assemble spawn options
	var options *C.FridaSpawnOptions
	var config spawnOptions

	for _, opt := range opts {
		opt(&config)
	}

	if (len(config.argv) > 0) || (len(config.env) > 0) || (config.cwd != "") {
		// Create spawn options
		options = C.frida_spawn_options_new()
		defer C.frida_unref(C.gpointer(unsafe.Pointer(options)))

		// Set argument values
		if len(config.argv) != 0 {
			// Build a NULL-terminated list of arguments
			argv := make([]*C.char, 0, len(config.argv)+1)

			for _, arg := range config.argv {
				carg := C.CString(arg)
				defer C.free(unsafe.Pointer(carg))

				argv = append(argv, carg)
			}

			argv = append(argv, nil)

			// Set argument values
			C.frida_spawn_options_set_argv(options, (**C.char)(unsafe.Pointer(&argv[0])), C.gint(len(config.argv)))
		}

		// Set environment variables
		if len(config.env) != 0 {
			// Build a NULL-terminated list of environment variables
			env := make([]*C.char, 0, len(config.env)+1)

			for key, value := range config.env {
				cenv := C.CString(key + "=" + value)
				defer C.free(unsafe.Pointer(cenv))

				env = append(env, cenv)
			}

			env = append(env, nil)

			// Set environment variables
			C.frida_spawn_options_set_env(options, (**C.char)(unsafe.Pointer(&env[0])), C.gint(len(config.env)))
		}

		// Set working directory
		if config.cwd != "" {
			ccwd := C.CString(config.cwd)
			defer C.free(unsafe.Pointer(ccwd))

			C.frida_spawn_options_set_cwd(options, ccwd)
		}
	}

	// Spawn process in suspended state
	var gErr *C.GError

	nameCopy := C.CString(name)
	defer C.free(unsafe.Pointer(nameCopy))

	pid := C.frida_device_spawn_sync(d.handle, nameCopy, options, cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return 0, fmt.Errorf("spawn process [name=%s]: %w", name, err)
	}

	if pid == 0 {
		return 0, fmt.Errorf("spawn process [name=%s]: empty", name)
	}

	return uint(pid), nil
}

// Resume resumes execution of the suspended process with the given PID.
func (d *Device) Resume(ctx context.Context, pid uint) error {
	// Validate input
	if pid == 0 {
		return errors.New("no pid given")
	}

	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return errDeviceClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Resume process
	var gErr *C.GError

	C.frida_device_resume_sync(d.handle, C.guint(pid), cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return fmt.Errorf("resume process [pid=%d]: %w", pid, err)
	}

	return nil
}

// Kill kills the process with the given PID.
func (d *Device) Kill(ctx context.Context, pid uint) error {
	// Validate input
	if pid == 0 {
		return errors.New("no pid given")
	}

	// Synchronize access
	d.mu.Lock()
	defer d.mu.Unlock()

	// Early exit if device is already closed
	if d.closed {
		return errDeviceClosed
	}

	// Create cancellable
	cancellable, releaseCancellable := newCancellable(ctx)
	defer releaseCancellable()

	// Kill process
	var gErr *C.GError

	C.frida_device_kill_sync(d.handle, C.guint(pid), cancellable, &gErr)
	if err := consumeGError(gErr); err != nil {
		return fmt.Errorf("kill process [pid=%d]: %w", pid, err)
	}

	return nil
}
