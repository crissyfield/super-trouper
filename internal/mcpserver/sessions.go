package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// sessionState contains the state of a Frida session created by the 'attach' tool.
type sessionState struct {
	deviceHandle string           // Handle of the owning device.
	session      *frida.Session   // Underlying Frida session.
	pid          uint             // PID of the attached process.
	evaluator    *frida.Evaluator // Persistent evaluator, created lazily by the 'evaluate' tool.
}

// lookupSessionState returns the state of the session with the given handle. The caller must hold the mutex.
func (s *MCPServer) lookupSessionState(handle string) (*sessionState, error) {
	state, ok := s.sessions[handle]
	if !ok {
		return nil, fmt.Errorf("unknown session handle [handle=%s]", handle)
	}

	return state, nil
}

// addSessionsTools registers the session tools.
func (s *MCPServer) addSessionsTools() {
	// Attach to a process
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "attach",
		Description: "Attaches to a process on a Frida device, either by PID or by name. Returns a session " +
			"handle used by the session tools.",
	}, s.attach)

	// Detach from a process
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "detach",
		Description: "Detaches from a process, closing all of its scripts and its session.",
	}, s.detach)

	// Evaluate a JavaScript statement
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "evaluate",
		Description: "Evaluates a JavaScript statement in an attached process and returns its JSON result. " +
			"The first call sets up a persistent evaluator in the session.",
	}, s.evaluate)
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

// attachInput contains the input arguments of the 'attach' tool.
type attachInput struct {
	Device string  `json:"device" jsonschema:"handle of the device owning the process"`
	PID    uint    `json:"pid,omitempty" jsonschema:"PID of the process to attach"`
	Name   string  `json:"name,omitempty" jsonschema:"name of the process to attach, matching is case-insensitive"`
	WaitMs float64 `json:"wait_ms,omitempty" jsonschema:"how long to wait for a process given by name to appear (in milliseconds)"`
}

// attachOutput contains the output of the 'attach' tool.
type attachOutput struct {
	Session string `json:"session" jsonschema:"handle of the session, used by the other session tools"`
	PID     uint   `json:"pid" jsonschema:"PID of the attached process"`
}

// attach implements the 'attach' tool.
func (s *MCPServer) attach(ctx context.Context, _ *mcp.CallToolRequest, in attachInput) (*mcp.CallToolResult, attachOutput, error) {
	// Validate input
	if (in.PID != 0) == (in.Name != "") {
		return nil, attachOutput{}, errors.New("exactly one of PID or name must be given")
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, attachOutput{}, err
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
			return nil, attachOutput{}, fmt.Errorf("find process: %w", err)
		}

		if process == nil {
			return nil, attachOutput{}, fmt.Errorf("process not found [name=%s]", in.Name)
		}

		pid = process.PID
	}

	// Attach to process
	session, err := state.device.Attach(ctx, pid)
	if err != nil {
		return nil, attachOutput{}, fmt.Errorf("attach process: %w", err)
	}

	// Register session
	handle := uuid.New().String()
	s.sessions[handle] = &sessionState{
		deviceHandle: in.Device,
		session:      session,
		pid:          pid,
	}

	return nil, attachOutput{Session: handle, PID: pid}, nil
}

// detachInput contains the input arguments of the 'detach' tool.
type detachInput struct {
	Session string `json:"session" jsonschema:"handle of the session to detach"`
}

// detachOutput contains the output of the 'detach' tool.
type detachOutput struct{}

// detach implements the 'detach' tool.
func (s *MCPServer) detach(ctx context.Context, _ *mcp.CallToolRequest, in detachInput) (*mcp.CallToolResult, detachOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up session
	state, err := s.lookupSessionState(in.Session)
	if err != nil {
		return nil, detachOutput{}, err
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

	return nil, detachOutput{}, nil
}

// evaluateInput contains the input arguments of the 'evaluate' tool.
type evaluateInput struct {
	Session   string `json:"session" jsonschema:"handle of the session to evaluate the statement in"`
	Statement string `json:"statement" jsonschema:"JavaScript statement to evaluate"`
}

// evaluate implements the 'evaluate' tool.
func (s *MCPServer) evaluate(ctx context.Context, _ *mcp.CallToolRequest, in evaluateInput) (*mcp.CallToolResult, any, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up session
	state, err := s.lookupSessionState(in.Session)
	if err != nil {
		return nil, nil, err
	}

	// Create evaluator lazily
	evaluator := state.evaluator

	if evaluator == nil {
		evaluator, err = frida.NewEvaluator(ctx, state.session)
		if err != nil {
			return nil, nil, fmt.Errorf("create evaluator: %w", err)
		}

		state.evaluator = evaluator
	}

	// Evaluate statement
	result, err := evaluator.Evaluate(ctx, in.Statement)
	if err != nil {
		return nil, nil, fmt.Errorf("evaluate JavaScript: %w", err)
	}

	// Decode JSON result
	var value any

	if err := json.Unmarshal(result, &value); err != nil {
		return nil, nil, fmt.Errorf("decode JavaScript result: %w", err)
	}

	return nil, value, nil
}
