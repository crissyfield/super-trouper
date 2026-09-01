package frida

/*
#include <stdint.h>
*/
import "C"

import (
	"runtime/cgo"
)

//export goFridaScriptMessage
func goFridaScriptMessage(message *C.char, handle C.uintptr_t) {
	evaluator, ok := cgo.Handle(handle).Value().(*evaluator)
	if !ok {
		return
	}

	select {
	case evaluator.messages <- C.GoString(message):
	default:
	}
}
