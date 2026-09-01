package cmd

import (
	"context"
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
	CmdServe.Flags().Uint("frida.pid", 0, "PID of the process to attach")
}

// runServe executes the 'serve' command.
func runServe(cmd *cobra.Command, _ []string) error {
	client, err := frida.New(cmd.Context(), frida.Config{Address: viper.GetString("frida.address")})
	if err != nil {
		return fmt.Errorf("connect to Frida server: %w", err)
	}
	defer closeFridaClient(client)

	slog.Info("Connected to Frida server",
		slog.String("device_id", client.DeviceID()),
		slog.String("device_name", client.DeviceName()),
		slog.String("frida_core_version", client.Version()),
	)

	applications, err := client.ListApplications(cmd.Context())
	if err != nil {
		return fmt.Errorf("list Frida applications: %w", err)
	}

	for _, application := range applications {
		slog.Info("Found Frida application",
			slog.String("identifier", application.Identifier),
			slog.String("name", application.Name),
			slog.Uint64("pid", uint64(application.PID)),
			slog.Bool("running", application.Running),
		)
	}

	pid := viper.GetUint("frida.pid")
	if err := client.AttachEvaluator(cmd.Context(), pid); err != nil {
		return fmt.Errorf("attach Frida evaluator: %w", err)
	}

	result, err := client.Evaluate(cmd.Context(), "Process.enumerateModules()")
	if err != nil {
		return fmt.Errorf("evaluate JavaScript: %w", err)
	}

	slog.Info("Evaluated JavaScript", slog.Uint64("pid", uint64(pid)), slog.String("result", string(result)))

	<-cmd.Context().Done()
	return nil
}

func closeFridaClient(client *frida.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Close(ctx); err != nil {
		slog.Error("Close Frida client", slog.Any("error", err))
	}
}
