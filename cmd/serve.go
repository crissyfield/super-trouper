package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// CmdServe defines the 'serve' command.
var CmdServe = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server.",
	RunE:  runServe,
}

func init() {
	CmdServe.Flags().String("frida.address", "", "Frida server address in host:port form")
	CmdServe.Flags().Bool("frida.usb", false, "Connect to the first detected USB device")
	CmdServe.Flags().Uint("frida.pid", 0, "PID of the process to attach")
}

// runServe executes the 'serve' command.
func runServe(cmd *cobra.Command, _ []string) error {
	// Connect to the configured Frida device.
	address := viper.GetString("frida.address")
	useUSB := viper.GetBool("frida.usb")
	if useUSB && (address != "") {
		return errors.New("frida address and USB options cannot be used together")
	}

	manager, err := frida.NewManager()
	if err != nil {
		return fmt.Errorf("create Frida manager: %w", err)
	}

	defer closeFridaManager(manager)

	var device *frida.Device
	if useUSB {
		device, err = manager.GetDeviceByType(cmd.Context(), frida.DeviceTypeUSB)
	} else {
		device, err = manager.AddRemoteDevice(cmd.Context(), address)
	}

	if err != nil {
		return fmt.Errorf("connect to Frida server: %w", err)
	}

	defer closeFridaDevice(device)

	slog.Info("Connected to Frida server",
		slog.String("device_id", device.ID()),
		slog.String("device_name", device.Name()),
		slog.String("frida_core_version", frida.Version()),
	)

	// List Frida apps
	apps, err := device.ListApplications(cmd.Context())
	if err != nil {
		return fmt.Errorf("list Frida applications: %w", err)
	}

	for _, app := range apps {
		slog.Info("Found Frida application",
			slog.String("identifier", app.Identifier),
			slog.String("name", app.Name),
			slog.Uint64("pid", uint64(app.PID)),
			slog.Bool("running", app.Running),
		)
	}

	// Attach Frida session
	session, err := device.Attach(cmd.Context(), viper.GetUint("frida.pid"))
	if err != nil {
		return fmt.Errorf("attach Frida session: %w", err)
	}

	defer closeFridaSession(session)

	// Create Frida evaluator
	evaluator, err := frida.NewEvaluator(cmd.Context(), session)
	if err != nil {
		return fmt.Errorf("create Frida evaluator: %w", err)
	}

	defer closeFridaEvaluator(evaluator)

	// Evaluate JavaScript
	result, err := evaluator.Evaluate(cmd.Context(), "Process.enumerateModules()")
	if err != nil {
		return fmt.Errorf("evaluate JavaScript: %w", err)
	}

	slog.Info("Evaluated JavaScript", slog.String("result", string(result)))

	return nil
}

// closeFridaManager closes the Frida manager with a timeout context.
func closeFridaManager(manager *frida.Manager) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := manager.Close(ctx); err != nil {
		slog.Error("Close Frida manager", slog.Any("error", err))
	}
}

// closeFridaDevice closes the Frida device with a timeout context.
func closeFridaDevice(device *frida.Device) {
	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close Frida device
	if err := device.Close(ctx); err != nil {
		slog.Error("Close Frida device", slog.Any("error", err))
	}
}

// closeFridaSession closes the Frida session with a timeout context.
func closeFridaSession(session *frida.Session) {
	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close Frida session
	if err := session.Close(ctx); err != nil {
		slog.Error("Close Frida session", slog.Any("error", err))
	}
}

// closeFridaEvaluator closes the Frida evaluator with a timeout context.
func closeFridaEvaluator(evaluator *frida.Evaluator) {
	// Create timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close Frida evaluator
	if err := evaluator.Close(ctx); err != nil {
		slog.Error("Close Frida evaluator", slog.Any("error", err))
	}
}
