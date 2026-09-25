package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// addThreadsTools registers the thread tools.
func (s *MCPServer) addThreadsTools() {
	// List process threads
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "thread_list",
		Description: "Lists the threads running in an attached process with their ID, state, and program counter.",
	}, s.threadList)
}

// threadInfo describes a thread running in an attached process.
type threadInfo struct {
	ID    uint   `json:"id" jsonschema:"OS-specific thread ID"`
	State string `json:"state" jsonschema:"thread state"`
	PC    string `json:"pc" jsonschema:"thread program counter as a hexadecimal string"`
}

// threadListInput contains the input arguments of the 'thread_list' tool.
type threadListInput struct {
	Session string `json:"session" jsonschema:"handle of the session to list threads in"`
}

// threadListOutput contains the output of the 'thread_list' tool.
type threadListOutput struct {
	Threads []threadInfo `json:"threads" jsonschema:"threads running in the process"`
}

// threadList implements the 'thread_list' tool.
func (s *MCPServer) threadList(ctx context.Context, _ *mcp.CallToolRequest, in threadListInput) (*mcp.CallToolResult, threadListOutput, error) {
	// Enumerate threads
	evaluator, err := s.sessionEvaluator(ctx, in.Session)
	if err != nil {
		return nil, threadListOutput{}, err
	}

	threads, err := evaluator.Evaluate[[]threadInfo](
		ctx,
		`
			Process.enumerateThreads().map(thread => ({
				id: thread.id,
				state: thread.state,
				pc: thread.context.pc.toString()
			}))
		`,
	)

	if err != nil {
		return nil, threadListOutput{}, fmt.Errorf("enumerate threads: %w", err)
	}

	return nil, threadListOutput{Threads: threads}, nil
}
