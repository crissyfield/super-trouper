package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// processInfo describes a process on a Frida device.
type processInfo struct {
	PID  uint   `json:"pid"`  // Process ID.
	Name string `json:"name"` // Process name.
}

// addProcessesTools registers the process tools.
func (s *MCPServer) addProcessesTools() {
	// List processes
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "process_list",
		Description: "Lists the processes running on a Frida device.",
	}, s.processList)
}

// processListInput contains the input arguments of the 'process_list' tool.
type processListInput struct {
	Device string `json:"device" jsonschema:"handle of the device to list the processes of"`
}

// processListOutput contains the output of the 'process_list' tool.
type processListOutput struct {
	Processes []processInfo `json:"processes" jsonschema:"the processes running on the device"`
}

// processList implements the 'process_list' tool.
func (s *MCPServer) processList(ctx context.Context, _ *mcp.CallToolRequest, in processListInput) (*mcp.CallToolResult, processListOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, processListOutput{}, err
	}

	// List processes
	processes, err := state.device.ListProcesses(ctx)
	if err != nil {
		return nil, processListOutput{}, fmt.Errorf("list processes: %w", err)
	}

	// Collect process information
	procInfos := make([]processInfo, len(processes))

	for i, process := range processes {
		procInfos[i] = processInfo{
			PID:  process.PID,
			Name: process.Name,
		}
	}

	return nil, processListOutput{Processes: procInfos}, nil
}
