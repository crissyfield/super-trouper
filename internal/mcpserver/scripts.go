package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// scriptState contains the state of a Frida script created by the 'script_create' tool.
type scriptState struct {
	sessionHandle string        // Handle of the owning session.
	script        *frida.Script // Underlying Frida script.
}

// lookupScriptState returns the state of the lookupScriptState with the given handle. The caller must hold the
// mutex.
func (s *MCPServer) lookupScriptState(handle string) (*scriptState, error) {
	state, ok := s.scripts[handle]
	if !ok {
		return nil, fmt.Errorf("unknown script handle [handle=%s]", handle)
	}

	return state, nil
}

// addScriptsTools registers the script tools.
func (s *MCPServer) addScriptsTools() {
	// Create a script
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "script_create",
		Description: "Creates a Frida script with the given JavaScript source in an attached session. The " +
			"script is created in an unloaded state; use script_load to load it.",
	}, s.scriptCreate)

	// Load a script
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "script_load",
		Description: "Loads a Frida script into its target process.",
	}, s.scriptLoad)

	// Unload a script
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "script_unload",
		Description: "Unloads a Frida script from its target process.",
	}, s.scriptUnload)

	// Close a script
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "script_close",
		Description: "Unloads a Frida script if loaded and releases its resources.",
	}, s.scriptClose)

	// Post a message to a script
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "script_post",
		Description: "Posts a JSON message to a Frida script.",
	}, s.scriptPost)

	// Read script messages
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "script_messages",
		Description: "Returns the messages sent by a Frida script. Messages are buffered (up to 256) and " +
			"should be drained regularly.",
	}, s.scriptMessages)
}

// closeFridaScripts closes the given Frida scripts with a timeout context and logs any error.
func closeFridaScripts(scripts ...*frida.Script) {
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close scripts
	for _, script := range scripts {
		if err := script.Close(timeoutCtx); err != nil {
			slog.Error("Close script", slog.Any("error", err))
		}
	}
}

// scriptCreateInput contains the input arguments of the 'script_create' tool.
type scriptCreateInput struct {
	Session string `json:"session" jsonschema:"handle of the session to create the script in"`
	Source  string `json:"source" jsonschema:"JavaScript source of the script"`
	Name    string `json:"name,omitempty" jsonschema:"name of the script"`
	Runtime string `json:"runtime,omitempty" jsonschema:"JavaScript runtime to run the script in, either default, qjs, or v8"`
}

// scriptCreateOutput contains the output of the 'script_create' tool.
type scriptCreateOutput struct {
	Script string `json:"script" jsonschema:"handle of the created script, used by the other script tools"`
}

// scriptCreate implements the 'script_create' tool.
func (s *MCPServer) scriptCreate(ctx context.Context, _ *mcp.CallToolRequest, in scriptCreateInput) (*mcp.CallToolResult, scriptCreateOutput, error) {
	// Validate runtime
	if (in.Runtime != "") && (in.Runtime != string(frida.ScriptRuntimeDefault)) && (in.Runtime != string(frida.ScriptRuntimeQJS)) && (in.Runtime != string(frida.ScriptRuntimeV8)) {
		return nil, scriptCreateOutput{}, fmt.Errorf("invalid runtime [runtime=%s]", in.Runtime)
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up session
	state, err := s.lookupSessionState(in.Session)
	if err != nil {
		return nil, scriptCreateOutput{}, err
	}

	// Assemble script options
	var options []frida.ScriptOption

	if in.Name != "" {
		options = append(options, frida.WithScriptName(in.Name))
	}

	if in.Runtime != "" {
		options = append(options, frida.WithScriptRuntime(frida.ScriptRuntime(in.Runtime)))
	}

	// Create script
	script, err := state.session.CreateScript(ctx, in.Source, options...)
	if err != nil {
		return nil, scriptCreateOutput{}, fmt.Errorf("create script: %w", err)
	}

	// Register script
	handle := uuid.New().String()
	s.scripts[handle] = &scriptState{
		sessionHandle: in.Session,
		script:        script,
	}

	return nil, scriptCreateOutput{Script: handle}, nil
}

// scriptLoadInput contains the input arguments of the 'script_load' tool.
type scriptLoadInput struct {
	Script string `json:"script" jsonschema:"handle of the script to load"`
}

// scriptLoadOutput contains the output of the 'script_load' tool.
type scriptLoadOutput struct{}

// scriptLoad implements the 'script_load' tool.
func (s *MCPServer) scriptLoad(ctx context.Context, _ *mcp.CallToolRequest, in scriptLoadInput) (*mcp.CallToolResult, scriptLoadOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up script
	state, err := s.lookupScriptState(in.Script)
	if err != nil {
		return nil, scriptLoadOutput{}, err
	}

	// Load script
	if err := state.script.Load(ctx); err != nil {
		return nil, scriptLoadOutput{}, fmt.Errorf("load script: %w", err)
	}

	return nil, scriptLoadOutput{}, nil
}

// scriptUnloadInput contains the input arguments of the 'script_unload' tool.
type scriptUnloadInput struct {
	Script string `json:"script" jsonschema:"handle of the script to unload"`
}

// scriptUnloadOutput contains the output of the 'script_unload' tool.
type scriptUnloadOutput struct{}

// scriptUnload implements the 'script_unload' tool.
func (s *MCPServer) scriptUnload(ctx context.Context, _ *mcp.CallToolRequest, in scriptUnloadInput) (*mcp.CallToolResult, scriptUnloadOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up script
	state, err := s.lookupScriptState(in.Script)
	if err != nil {
		return nil, scriptUnloadOutput{}, err
	}

	// Unload script
	if err := state.script.Unload(ctx); err != nil {
		return nil, scriptUnloadOutput{}, fmt.Errorf("unload script: %w", err)
	}

	return nil, scriptUnloadOutput{}, nil
}

// scriptCloseInput contains the input arguments of the 'script_close' tool.
type scriptCloseInput struct {
	Script string `json:"script" jsonschema:"handle of the script to close"`
}

// scriptCloseOutput contains the output of the 'script_close' tool.
type scriptCloseOutput struct{}

// scriptClose implements the 'script_close' tool.
func (s *MCPServer) scriptClose(ctx context.Context, _ *mcp.CallToolRequest, in scriptCloseInput) (*mcp.CallToolResult, scriptCloseOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up script
	state, err := s.lookupScriptState(in.Script)
	if err != nil {
		return nil, scriptCloseOutput{}, err
	}

	// Remove script from state
	delete(s.scripts, in.Script)

	// Close script
	if err := state.script.Close(ctx); err != nil {
		return nil, scriptCloseOutput{}, fmt.Errorf("close script: %w", err)
	}

	return nil, scriptCloseOutput{}, nil
}

// scriptPostInput contains the input arguments of the 'script_post' tool.
type scriptPostInput struct {
	Script  string `json:"script" jsonschema:"handle of the script to post the message to"`
	Message string `json:"message" jsonschema:"JSON message to post to the script"`
}

// scriptPostOutput contains the output of the 'script_post' tool.
type scriptPostOutput struct{}

// scriptPost implements the 'script_post' tool.
func (s *MCPServer) scriptPost(_ context.Context, _ *mcp.CallToolRequest, in scriptPostInput) (*mcp.CallToolResult, scriptPostOutput, error) {
	// Validate message
	if !json.Valid([]byte(in.Message)) {
		return nil, scriptPostOutput{}, fmt.Errorf("message is not valid JSON [message=%s]", in.Message)
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up script
	state, err := s.lookupScriptState(in.Script)
	if err != nil {
		return nil, scriptPostOutput{}, err
	}

	// Post message
	if err := state.script.Post(in.Message, nil); err != nil {
		return nil, scriptPostOutput{}, fmt.Errorf("post message: %w", err)
	}

	return nil, scriptPostOutput{}, nil
}

// scriptMessagesInput contains the input arguments of the 'script_messages' tool.
type scriptMessagesInput struct {
	Script    string  `json:"script" jsonschema:"handle of the script to read the messages of"`
	TimeoutMs float64 `json:"timeout_ms,omitempty" jsonschema:"how long to wait for the first message to arrive (in milliseconds)"`
}

// scriptMessagesOutput contains the output of the 'script_messages' tool.
type scriptMessagesOutput struct {
	Messages []any `json:"messages" jsonschema:"the messages sent by the script, each decoded from JSON"`
}

// scriptMessages implements the 'script_messages' tool.
func (s *MCPServer) scriptMessages(_ context.Context, _ *mcp.CallToolRequest, in scriptMessagesInput) (*mcp.CallToolResult, scriptMessagesOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up script
	state, err := s.lookupScriptState(in.Script)
	if err != nil {
		return nil, scriptMessagesOutput{}, err
	}

	// Wait for the first message
	values := []any{}
	messages := state.script.Messages()

	if timeout := time.Duration(in.TimeoutMs * float64(time.Millisecond)); timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case message := <-messages:
			values = append(values, decodeMessage(message))

		case <-timer.C:
			// No message arrived in time
		}
	}

	// Drain buffered messages
	for {
		select {
		case message := <-messages:
			values = append(values, decodeMessage(message))
			continue

		default:
			// No more buffered messages
		}

		break
	}

	return nil, scriptMessagesOutput{Messages: values}, nil
}

// decodeMessage converts a script message into a JSON value, falling back to the raw JSON string.
func decodeMessage(message frida.ScriptMessage) any {
	var value any

	if err := json.Unmarshal([]byte(message.JSON), &value); err != nil {
		return message.JSON
	}

	return value
}
