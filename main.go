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
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/crissyfield/super-trouper/internal/codeshare"
	"github.com/crissyfield/super-trouper/internal/frida"
	"github.com/crissyfield/super-trouper/internal/mcpserver"
)

// Version is the application version, injected at build time via ldflags.
var Version = "unknown"

// CmdSuperTrouper defines the main command.
var cmdMain = &cobra.Command{
	Use:               "super-trouper [flags]",
	Long:              "MCP server for the Frida reverse engineering toolkit.",
	Args:              cobra.NoArgs,
	Version:           Version,
	SilenceErrors:     true,
	SilenceUsage:      true,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	PersistentPreRunE: setup,
	RunE:              runMCP,
}

func init() {
	// Define command line flags.
	cmdMain.PersistentFlags().String("logging.level", "info", "verbosity of logging output")
	cmdMain.PersistentFlags().Bool("logging.json", false, "change logging format to JSON")
}

// main is the main entry point of the command.
func main() {
	// Create a context that is canceled when an interrupt signal is received.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Execute the main command.
	if err := cmdMain.ExecuteContext(ctx); err != nil {
		slog.Error("Unable to execute command", slog.Any("error", err))
		os.Exit(1)
	}
}

// setup configures Viper and slog.
//
// Configuration options can be set via the command line, via a configuration file (in the current folder, at
// "/etc/super-trouper/config.yaml" or at "~/.config/super-trouper/config.yaml"), and via environment variables
// (all uppercase and prefixed with "SUPER_TROUPER_").
func setup(command *cobra.Command, _ []string) error {
	// Bind command flags
	err := viper.BindPFlags(command.Flags())
	if err != nil {
		return fmt.Errorf("bind command line flags: %w", err)
	}

	// Configure environment variables
	viper.SetEnvPrefix("SUPER_TROUPER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Search standard configuration paths
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/super-trouper")

	if home, err := os.UserHomeDir(); err == nil {
		viper.AddConfigPath(filepath.Join(home, ".config", "super-trouper"))
	}

	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("read config file: %w", err)
		}
	}

	// Configure logging
	var level slog.Level

	err = level.UnmarshalText([]byte(viper.GetString("logging.level")))
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	var handler slog.Handler

	if viper.GetBool("logging.json") {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}

	slog.SetDefault(slog.New(handler))
	slog.SetLogLoggerLevel(slog.LevelDebug)

	return nil
}

// runMCP runs the MCP server.
func runMCP(command *cobra.Command, _ []string) error {
	// Create Frida manager
	manager, err := frida.NewManager(frida.WithManagerLogger(slog.Default()))
	if err != nil {
		return fmt.Errorf("create Frida manager: %w", err)
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := manager.Close(ctx); err != nil {
			slog.Error("Close Frida manager", slog.Any("error", err))
		}
	}()

	// Create CodeShare client
	codeshare := codeshare.New()

	// Create MCP server
	server := mcpserver.New(manager, codeshare, command.Version)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Close(ctx); err != nil {
			slog.Error("Close MCP server", slog.Any("error", err))
		}
	}()

	// Run MCP server
	slog.Info("Starting MCP server")

	err = server.Run(command.Context())
	if (err != nil) && (!errors.Is(err, context.Canceled)) {
		return fmt.Errorf("run MCP server: %w", err)
	}

	slog.Info("Stopping MCP server")

	return nil
}
