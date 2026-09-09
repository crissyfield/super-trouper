// Package mcpserver implements the MCP server exposed by the 'mcp' command.
package mcpserver

import (
	"context"
	"errors"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// MCPServer is a stateful MCP server that exposes the Frida bindings of a Frida manager as tools.
type MCPServer struct {
	server   *mcp.Server              // Underlying MCP server.
	manager  *frida.Manager           // Frida manager providing the device bindings.
	mu       sync.Mutex               // Guards all state maps below.
	keys     map[string]string        // Device handles, keyed by idempotency connect key.
	devices  map[string]*deviceState  // Connected devices, keyed by opaque handle.
	sessions map[string]*sessionState // Attached sessions, keyed by opaque handle.
	scripts  map[string]*scriptState  // Created scripts, keyed by opaque handle.
}

// New creates a new MCP server that exposes the Frida bindings of the given manager as tools.
func New(manager *frida.Manager, version string) *MCPServer {
	// Create server instance
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "super-trouper", Version: version}, &mcp.ServerOptions{
		Instructions: "Tools for the Frida dynamic instrumentation toolkit. Connect to a device with " +
			"device_connect, list its applications and processes, attach to a process, evaluate " +
			"JavaScript in the target, and manage custom scripts.",
	})

	server := &MCPServer{
		server:   mcpServer,
		manager:  manager,
		keys:     make(map[string]string),
		devices:  make(map[string]*deviceState),
		sessions: make(map[string]*sessionState),
		scripts:  make(map[string]*scriptState),
	}

	// Add tools
	server.addDevicesTools()
	server.addApplicationsTools()
	server.addProcessesTools()
	server.addSessionsTools()
	server.addScriptsTools()

	return server
}

// Run runs the MCP server over the stdio transport.
func (s *MCPServer) Run(ctx context.Context) error {
	return s.server.Run(ctx, &mcp.StdioTransport{})
}

// Close closes all devices, sessions, and scripts created through the tools of the server.
func (s *MCPServer) Close(ctx context.Context) error {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close scripts
	var closeErr error

	for _, state := range s.scripts {
		err := state.script.Close(ctx)
		if err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}

	// Close sessions
	for _, state := range s.sessions {
		// Close evaluator if present
		if state.evaluator != nil {
			err := state.evaluator.Close(ctx)
			if err != nil {
				closeErr = errors.Join(closeErr, err)
			}
		}

		// Close session
		err := state.session.Close(ctx)
		if err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}

	// Close devices
	for _, state := range s.devices {
		err := state.device.Close(ctx)
		if err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}

	// Clean up
	s.keys = make(map[string]string)
	s.devices = make(map[string]*deviceState)
	s.sessions = make(map[string]*sessionState)
	s.scripts = make(map[string]*scriptState)

	return closeErr
}
