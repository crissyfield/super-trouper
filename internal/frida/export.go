package frida

/*
#include <stdint.h>
*/
import "C"

import "runtime/cgo"

// This will be called from within C when a script message is received. It will forward the message to the
// proper Script instance.
//
//export goFridaScriptMessage
func goFridaScriptMessage(message *C.char, handle C.uintptr_t) {
	// Find proper script instance
	script, ok := cgo.Handle(handle).Value().(*Script)
	if !ok || script.closed {
		return
	}

	// Non-blocking send:
	// If the message buffer channel is full, the message will be dropped!
	select {
	case script.messages <- C.GoString(message):
	default:
	}
}
