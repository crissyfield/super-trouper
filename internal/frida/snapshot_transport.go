package frida

/*
#include <frida-core.h>
*/
import "C"

// SnapshotTransport selects how a script snapshot is delivered to the target process.
type SnapshotTransport string

// Snapshot transports supported by Frida.
const (
	// SnapshotTransportInline delivers the snapshot inline with the script creation request.
	SnapshotTransportInline SnapshotTransport = "inline"

	// SnapshotTransportSharedMemory delivers the snapshot through shared memory.
	SnapshotTransportSharedMemory SnapshotTransport = "shared-memory"
)

// snapshotTransportToFrida converts a Go SnapshotTransport to a C.FridaSnapshotTransport, reporting whether the
// snapshot transport is valid. The empty transport maps to Frida's default transport.
func snapshotTransportToFrida(transport SnapshotTransport) (C.FridaSnapshotTransport, bool) {
	switch transport {
	case SnapshotTransportInline:
		// Frida's default transport
		return C.FRIDA_SNAPSHOT_TRANSPORT_INLINE, true

	case SnapshotTransportSharedMemory:
		// Shared memory transport
		return C.FRIDA_SNAPSHOT_TRANSPORT_SHARED_MEMORY, true

	default:
		// Invalid transport
		return 0, false
	}
}
