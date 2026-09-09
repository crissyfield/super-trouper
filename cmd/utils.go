package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/crissyfield/super-trouper/internal/frida"
)

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
