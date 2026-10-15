package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/codeshare"
	"github.com/crissyfield/super-trouper/internal/frida"
)

var errMCPServerClosed = errors.New("mcp server already closed")

// MCPServer is a stateful MCP server that exposes the Frida bindings of a Frida manager as tools.
type MCPServer struct {
	server    *mcp.Server              // Underlying MCP server.
	manager   *frida.Manager           // Frida manager providing the device bindings.
	codeshare *codeshare.CodeShare     // CodeShare client providing the CodeShare bindings.
	mu        sync.Mutex               // Guards all state maps below.
	closed    bool                     // Whether server resources were released.
	keys      map[string]string        // Device handles, keyed by idempotency connect key.
	devices   map[string]*deviceState  // Connected devices, keyed by opaque handle.
	sessions  map[string]*sessionState // Attached sessions, keyed by opaque handle.
	patterns  map[string]*patternState // Managed Pattern projects, keyed by opaque handle.
	scripts   map[string]*scriptState  // Created scripts, keyed by opaque handle.
	workspace string                   // Shared Frida workspace containing managed Pattern projects.
}

// New creates a new MCP server that exposes the Frida bindings of the given manager as tools.
func New(manager *frida.Manager, codeShare *codeshare.CodeShare, version string) (*MCPServer, error) {
	// Resolve Pattern workspace
	workspace, err := frida.WorkspaceRoot("")
	if err != nil {
		return nil, fmt.Errorf("resolve Pattern workspace: %w", err)
	}

	// Load persisted Pattern projects
	patterns, err := loadPatternProjects(workspace)
	if err != nil {
		return nil, fmt.Errorf("load pattern projects: %w", err)
	}

	// Create server instance
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "super-trouper", Version: version}, &mcp.ServerOptions{
		Instructions: "Tools for the Frida dynamic instrumentation toolkit. Connect to a device with " +
			"device_connect, list its applications and processes, attach to a process with session_attach, " +
			"or evaluate TypeScript and JavaScript in the target with session_eval. Manage custom scripts " +
			"and use the codeshare tools to discover and fetch scripts from Frida CodeShare.",
	})

	server := &MCPServer{
		server:    mcpServer,
		manager:   manager,
		codeshare: codeShare,
		keys:      make(map[string]string),
		devices:   make(map[string]*deviceState),
		sessions:  make(map[string]*sessionState),
		patterns:  patterns,
		scripts:   make(map[string]*scriptState),
		workspace: workspace,
	}

	// Add tools
	server.addApplicationsTools()
	server.addCodeShareTools()
	server.addDevicesTools()
	server.addMemoryTools()
	server.addModulesTools()
	server.addPackagesTools()
	server.addPatternsTools()
	server.addProcessesTools()
	server.addScriptsTools()
	server.addSessionsTools()
	server.addStatusTools()
	server.addThreadsTools()

	return server, nil
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

	// Early exit if already closed
	if s.closed {
		return nil
	}

	s.closed = true

	// Close scripts
	var closeErr error

	for _, scrp := range s.scripts {
		err := scrp.script.Close(ctx)
		if err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close script: %w", err))
		}
	}

	// Close Pattern modules
	for _, patt := range s.patterns {
		// Close modules
		for _, module := range patt.modules {
			module.Close()
		}
	}

	// Close sessions
	for _, sess := range s.sessions {
		// Close evaluator if present
		if sess.evaluator != nil {
			err := sess.evaluator.Close(ctx)
			if err != nil {
				closeErr = errors.Join(closeErr, fmt.Errorf("close evaluator: %w", err))
			}
		}

		// Close session
		err := sess.session.Close(ctx)
		if err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close session: %w", err))
		}
	}

	// Close devices
	for _, state := range s.devices {
		err := state.device.Close(ctx)
		if err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("close device: %w", err))
		}
	}

	// Clean up
	s.keys = make(map[string]string)
	s.devices = make(map[string]*deviceState)
	s.sessions = make(map[string]*sessionState)
	s.patterns = make(map[string]*patternState)
	s.scripts = make(map[string]*scriptState)

	return closeErr
}
