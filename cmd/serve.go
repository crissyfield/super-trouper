package cmd

import "github.com/spf13/cobra"

// CmdServe defines the 'serve' command.
var CmdServe = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server.",
	Run:   runServe,
}

// runServe executes the 'serve' command.
func runServe(_ *cobra.Command, _ []string) {
	// TODO
}
