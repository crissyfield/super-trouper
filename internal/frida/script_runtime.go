package frida

/*
#include <frida-core.h>
*/
import "C"

// ScriptRuntime selects the JavaScript runtime used by a script.
type ScriptRuntime string

// Script runtimes supported by Frida.
const (
	// ScriptRuntimeDefault indicates that Frida picks its default script runtime.
	ScriptRuntimeDefault ScriptRuntime = "default"

	// ScriptRuntimeQJS indicates the QuickJS runtime.
	ScriptRuntimeQJS ScriptRuntime = "qjs"

	// ScriptRuntimeV8 indicates the V8 runtime.
	ScriptRuntimeV8 ScriptRuntime = "v8"
)

// scriptRuntimeToFrida converts a Go ScriptRuntime to a C.FridaScriptRuntime, reporting whether the script
// runtime is valid. The empty runtime maps to Frida's default runtime.
func scriptRuntimeToFrida(runtime ScriptRuntime) (C.FridaScriptRuntime, bool) {
	switch runtime {
	case ScriptRuntimeDefault:
		// Frida's default runtime
		return C.FRIDA_SCRIPT_RUNTIME_DEFAULT, true
	case ScriptRuntimeQJS:
		// QuickJS runtime
		return C.FRIDA_SCRIPT_RUNTIME_QJS, true
	case ScriptRuntimeV8:
		// V8 runtime
		return C.FRIDA_SCRIPT_RUNTIME_V8, true
	default:
		// Invalid runtime
		return 0, false
	}
}
