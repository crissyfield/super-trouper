package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// sessionState contains the state of a Frida session created by the 'session_attach' tool.
type sessionState struct {
	deviceHandle string           // Handle of the owning device.
	session      *frida.Session   // Underlying Frida session.
	pid          uint             // PID of the attached process.
	evaluator    *frida.Evaluator // Persistent evaluator, created lazily by the 'session_eval' tool.
}

// addSessionsTools registers the session tools.
func (s *MCPServer) addSessionsTools() {
	// Attach to a process
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "session_attach",
		Description: "Attaches to a process on a Frida device, either by PID or by name. Returns a session " +
			"handle used by the session tools.",
	}, s.sessionAttach)

	// Detach from a process
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "session_detach",
		Description: "Detaches from a process, closing all of its scripts and its session.",
	}, s.sessionDetach)

	// Evaluate a JavaScript statement
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "session_eval",
		Description: "Evaluates a JavaScript statement in an attached process and returns its JSON result. " +
			"The first call sets up a persistent evaluator in the session.",
	}, s.sessionEval)
}

// lookupSessionState returns the state of the session with the given handle. The caller must hold the mutex.
func (s *MCPServer) lookupSessionState(handle string) (*sessionState, error) {
	state, ok := s.sessions[handle]
	if !ok {
		return nil, fmt.Errorf("unknown session handle [handle=%s]", handle)
	}

	return state, nil
}

// sessionEvaluator returns the persistent evaluator of the specified session, creating it on first use.
func (s *MCPServer) sessionEvaluator(ctx context.Context, handle string) (*frida.Evaluator, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up session
	state, err := s.lookupSessionState(handle)
	if err != nil {
		return nil, err
	}

	// Create evaluator lazily
	if state.evaluator == nil {
		evaluator, err := s.manager.NewEvaluator(ctx, state.session, allBridgePackages())
		if err != nil {
			return nil, fmt.Errorf("create evaluator: %w", err)
		}

		state.evaluator = evaluator
	}

	return state.evaluator, nil
}

// closeFridaSessions closes the given Frida sessions with a timeout context and logs any error.
func closeFridaSessions(sessions ...*frida.Session) {
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close sessions
	for _, session := range sessions {
		if err := session.Close(timeoutCtx); err != nil {
			slog.Error("Close session", slog.Any("error", err))
		}
	}
}

// sessionAttachInput contains the input arguments of the 'session_attach' tool.
type sessionAttachInput struct {
	Device string  `json:"device" jsonschema:"handle of the device owning the process"`
	PID    uint    `json:"pid,omitempty" jsonschema:"PID of the process to attach"`
	Name   string  `json:"name,omitempty" jsonschema:"name of the process to attach, matching is case-insensitive"`
	WaitMs float64 `json:"wait_ms,omitempty" jsonschema:"how long to wait for a process given by name to appear (in milliseconds)"`
}

// sessionAttachOutput contains the output of the 'session_attach' tool.
type sessionAttachOutput struct {
	Session string `json:"session" jsonschema:"handle of the session, used by the other session tools"`
	PID     uint   `json:"pid" jsonschema:"PID of the attached process"`
}

// sessionAttach implements the 'session_attach' tool.
func (s *MCPServer) sessionAttach(ctx context.Context, _ *mcp.CallToolRequest, in sessionAttachInput) (*mcp.CallToolResult, sessionAttachOutput, error) {
	// Validate input
	if (in.PID != 0) == (in.Name != "") {
		return nil, sessionAttachOutput{}, errors.New("exactly one of PID or name must be given")
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, sessionAttachOutput{}, err
	}

	// Resolve target process by name
	pid := in.PID

	if in.Name != "" {
		// Assemble match options
		var options []frida.ProcessMatchOption

		if in.WaitMs > 0 {
			options = append(options, frida.WithProcessMatchTimeout(uint(in.WaitMs)))
		}

		// Find process by name
		process, err := state.device.FindProcessByName(ctx, in.Name, options...)
		if err != nil {
			return nil, sessionAttachOutput{}, fmt.Errorf("find process: %w", err)
		}

		if process == nil {
			return nil, sessionAttachOutput{}, fmt.Errorf("process not found [name=%s]", in.Name)
		}

		pid = process.PID
	}

	// Attach to process
	session, err := state.device.Attach(ctx, pid)
	if err != nil {
		return nil, sessionAttachOutput{}, fmt.Errorf("attach process: %w", err)
	}

	// Register session
	handle := uuid.New().String()
	s.sessions[handle] = &sessionState{
		deviceHandle: in.Device,
		session:      session,
		pid:          pid,
	}

	return nil, sessionAttachOutput{Session: handle, PID: pid}, nil
}

// sessionDetachInput contains the input arguments of the 'session_detach' tool.
type sessionDetachInput struct {
	Session string `json:"session" jsonschema:"handle of the session to detach"`
}

// sessionDetachOutput contains the output of the 'session_detach' tool.
type sessionDetachOutput struct{}

// sessionDetach implements the 'session_detach' tool.
func (s *MCPServer) sessionDetach(ctx context.Context, _ *mcp.CallToolRequest, in sessionDetachInput) (*mcp.CallToolResult, sessionDetachOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up session
	state, err := s.lookupSessionState(in.Session)
	if err != nil {
		return nil, sessionDetachOutput{}, err
	}

	// Collect session scripts and remove the session from state
	var scripts []*frida.Script

	for handle, script := range s.scripts {
		if script.sessionHandle == in.Session {
			scripts = append(scripts, script.script)
			delete(s.scripts, handle)
		}
	}

	delete(s.sessions, in.Session)

	// Close evaluator, scripts, and session
	if state.evaluator != nil {
		if err := state.evaluator.Close(ctx); err != nil {
			slog.Error("Close evaluator", slog.Any("error", err))
		}
	}

	closeFridaScripts(scripts...)
	closeFridaSessions(state.session)

	return nil, sessionDetachOutput{}, nil
}

// sessionEvalInput contains the input arguments of the 'session_eval' tool.
type sessionEvalInput struct {
	Session   string `json:"session" jsonschema:"handle of the session to evaluate the statement in"`
	Statement string `json:"statement" jsonschema:"JavaScript statement to evaluate"`
}

// sessionEval implements the 'session_eval' tool.
func (s *MCPServer) sessionEval(ctx context.Context, _ *mcp.CallToolRequest, in sessionEvalInput) (*mcp.CallToolResult, any, error) {
	// Resolve evaluator
	evaluator, err := s.sessionEvaluator(ctx, in.Session)
	if err != nil {
		return nil, nil, err
	}

	// Evaluate statement
	value, err := evaluator.Evaluate[any](ctx, in.Statement)
	if err != nil {
		return nil, nil, err
	}

	return nil, value, nil
}
