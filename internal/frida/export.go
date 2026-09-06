package frida

/*
#include <stdint.h>
#include <frida-core.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

// This will be called from within C when a script message is received. It will forward the message to the
// proper Script instance.
//
//export goFridaScriptMessage
func goFridaScriptMessage(message *C.char, data unsafe.Pointer, dataSize C.gsize, handle C.uintptr_t) {
	// Find proper script instance
	script, ok := cgo.Handle(handle).Value().(*Script)
	if !ok {
		return
	}

	// Copy binary payload
	var payload []byte

	if dataSize > 0 {
		payload = C.GoBytes(data, C.int(dataSize))
	}

	// Forward message to the script instance
	script.handleMessage(C.GoString(message), payload)
}
