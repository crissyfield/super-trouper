package cmd

import (
	"log/slog"

	"github.com/spf13/cobra"
)

// CmdMcp defines the 'mcp' command.
var CmdMcp = &cobra.Command{
	Use:   "mcp",
	Short: "Run the MCP server.",
	RunE:  runMcp,
}

// runMcp executes the 'mcp' command.
func runMcp(_ *cobra.Command, _ []string) error {
	slog.Info("MCP server is not implemented yet")

	return nil
}
