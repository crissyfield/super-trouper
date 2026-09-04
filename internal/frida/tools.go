package frida

/*
#include <frida-core.h>
*/
import "C"

import (
	"context"
	"errors"
	"unsafe"
)

// newCancellable creates a new GIO cancellable and returns a function to release it.
func newCancellable(ctx context.Context) (*C.GCancellable, func()) {
	// Create cancellable
	cancellable := C.g_cancellable_new()
	done := make(chan struct{})

	stop := context.AfterFunc(ctx, func() {
		// Cancel operation
		C.g_cancellable_cancel(cancellable)

		// Signal completion
		close(done)
	})

	releaseCancellable := func() {
		// Stop cancellation association
		if !stop() {
			// Wait for cancellation to complete
			<-done
		}

		// Release cancellable
		C.g_object_unref(C.gpointer(unsafe.Pointer(cancellable)))
	}

	return cancellable, releaseCancellable
}

// consumeGError converts a GError to a Go error and frees the GError.
func consumeGError(gErr *C.GError) error {
	// Early exit if no error
	if gErr == nil {
		return nil
	}

	defer C.g_error_free(gErr)

	// Convert GError to Go error
	return errors.New(C.GoString((*C.char)(unsafe.Pointer(gErr.message))))
}
