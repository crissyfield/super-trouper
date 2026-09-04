package frida

/*
#include <frida-core.h>
*/
import "C"

import "sync"

var (
	// Number of active managers using the Frida library.
	libManagerCount uint

	// Mutex to protect access to libManagerCount.
	libManagerCountMu sync.Mutex
)

// Version returns the Frida Core version of the linked library.
func Version() string {
	return C.GoString(C.frida_version_string())
}

// acquireLibrary initializes the Frida library if it hasn't been initialized yet.
func acquireLibrary() {
	// Synchronize access
	libManagerCountMu.Lock()
	defer libManagerCountMu.Unlock()

	if libManagerCount == 0 {
		// Initialize Frida library
		C.frida_init()
	}

	libManagerCount++
}

// releaseLibrary deinitializes the Frida library if there are no more active managers using it.
func releaseLibrary() {
	// Synchronize access
	libManagerCountMu.Lock()
	defer libManagerCountMu.Unlock()

	libManagerCount--
	if libManagerCount == 0 {
		// Deinitialize Frida library
		C.frida_deinit()
	}
}
