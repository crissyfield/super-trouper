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

// valueFromVariant converts a GVariant to the closest Go representation. Unsupported types are returned as
// their GVariant print representation.
func valueFromVariant(variant *C.GVariant) any {
	// Convert based on the GVariant type
	switch C.GoString(C.g_variant_get_type_string(variant)) {
	case "s":
		// GVariant string
		return C.GoString(C.g_variant_get_string(variant, nil))
	case "b":
		// GVariant boolean
		return C.g_variant_get_boolean(variant) != 0
	case "y":
		// GVariant byte
		return uint8(C.g_variant_get_byte(variant))
	case "n":
		// GVariant int16
		return int16(C.g_variant_get_int16(variant))
	case "q":
		// GVariant uint16
		return uint16(C.g_variant_get_uint16(variant))
	case "i":
		// GVariant int32
		return int32(C.g_variant_get_int32(variant))
	case "u":
		// GVariant uint32
		return uint32(C.g_variant_get_uint32(variant))
	case "x":
		// GVariant int64
		return int64(C.g_variant_get_int64(variant))
	case "t":
		// GVariant uint64
		return uint64(C.g_variant_get_uint64(variant))
	case "d":
		// GVariant double
		return float64(C.g_variant_get_double(variant))
	default:
		// Fall back to the GVariant print representation
		printed := C.g_variant_print(variant, 1)
		defer C.g_free(C.gpointer(unsafe.Pointer(printed)))

		return C.GoString(printed)
	}
}
