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
	if !ok || script.closed {
		return
	}

	// Copy binary payload
	var payload []byte

	if dataSize > 0 {
		payload = C.GoBytes(data, C.int(dataSize))
	}

	// Non-blocking send:
	// If the message buffer channel is full, the message will be dropped!
	select {
	case script.messages <- ScriptMessage{JSON: C.GoString(message), Data: payload}:
	default:
	}
}
