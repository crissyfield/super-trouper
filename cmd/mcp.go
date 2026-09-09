package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/crissyfield/super-trouper/internal/frida"
	"github.com/crissyfield/super-trouper/internal/mcpserver"
)

// CmdMcp defines the 'mcp' command.
var CmdMcp = &cobra.Command{
	Use:   "mcp",
	Short: "Run the MCP server.",
	RunE:  runMcp,
}

// runMcp executes the 'mcp' command.
func runMcp(cmd *cobra.Command, _ []string) error {
	// Create Frida manager
	manager, err := frida.NewManager(frida.WithManagerLogger(slog.Default()))
	if err != nil {
		return fmt.Errorf("create Frida manager: %w", err)
	}

	defer closeFridaManager(manager)

	// Create MCP server
	server := mcpserver.New(manager, cmd.Root().Version)
	defer closeMCPServer(server)

	// Run MCP server
	slog.Info("Starting MCP server")

	err = server.Run(cmd.Context())
	if (err != nil) && (!errors.Is(err, context.Canceled)) {
		return fmt.Errorf("run MCP server: %w", err)
	}

	slog.Info("MCP server stopped")

	return nil
}

// closeMCPServer closes the MCP server with a timeout context.
func closeMCPServer(server *mcpserver.MCPServer) {
	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close MCP server
	if err := server.Close(ctx); err != nil {
		slog.Error("Close MCP server", slog.Any("error", err))
	}
}
