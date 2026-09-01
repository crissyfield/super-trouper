package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/crissyfield/super-trouper/cmd"
)

// Version is the application version, injected at build time via ldflags.
var Version = "unknown"

// CmdRoot defines the root command.
var CmdRoot = &cobra.Command{
	Use:               "super-trouper [flags] [command]",
	Long:              "MCP server for the Frida reverse engineering toolkit.",
	Args:              cobra.ArbitraryArgs,
	Version:           Version,
	SilenceErrors:     true,
	SilenceUsage:      true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	PersistentPreRunE: setup,
}

// Initialize command options
func init() {
	// Logging options
	CmdRoot.PersistentFlags().String("logging.level", "info", "verbosity of logging output")
	CmdRoot.PersistentFlags().Bool("logging.json", false, "change logging format to JSON")

	// Register sub-command
	CmdRoot.AddCommand(cmd.CmdServe)
}

// setup will set up configuration management and logging.
//
// Configuration options can be set via the command line, via a configuration file (in the current folder, at
// "/etc/super-trouper/config.yaml" or at "~/.config/super-trouper/config.yaml"), and via environment variables
// (all uppercase and prefixed with "SUPER_TROUPER_").
func setup(cmd *cobra.Command, args []string) error {
	// Connect all options to Viper
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return fmt.Errorf("bind command line flags: %w", err)
	}

	// Environment variables
	viper.SetEnvPrefix("SUPER_TROUPER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Configuration file
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/super-trouper")

	if home, err := os.UserHomeDir(); err == nil {
		viper.AddConfigPath(filepath.Join(home, ".config", "super-trouper"))
	}

	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		// Don't fail if config not found
		if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("read config file: %w", err)
		}
	}

	// Logging
	var level slog.Level

	err = level.UnmarshalText([]byte(viper.GetString("logging.level")))
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	var handler slog.Handler

	if viper.GetBool("logging.json") {
		// Use JSON handler
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	} else {
		// Use text handler
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}

	slog.SetDefault(slog.New(handler))
	slog.SetLogLoggerLevel(slog.LevelDebug)

	return nil
}

// main is the main entry point of the command.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := CmdRoot.ExecuteContext(ctx); err != nil {
		slog.Error("Unable to execute command", slog.Any("error", err))
		os.Exit(1)
	}
}
