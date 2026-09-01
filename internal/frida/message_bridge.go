package frida

/*
#include <stdint.h>
#include <frida-core.h>

extern void goFridaScriptMessage(const gchar * message, uintptr_t handle);

static void
on_script_message(FridaScript * script,
                  const gchar * message,
                  GBytes * data,
                  gpointer user_data)
{
  (void) script;
  (void) data;
  goFridaScriptMessage(message, (uintptr_t) user_data);
}

static gulong
connect_script_message(FridaScript * script,
                       uintptr_t handle)
{
  return g_signal_connect(script, "message", G_CALLBACK(on_script_message), (gpointer) handle);
}

static void
disconnect_script_message(FridaScript * script,
                          gulong handler)
{
  g_signal_handler_disconnect(script, handler);
}
*/
import "C"

import "unsafe"

func connectScriptMessage(script unsafe.Pointer, handle uintptr) uintptr {
	return uintptr(C.connect_script_message((*C.FridaScript)(script), C.uintptr_t(handle)))
}

func disconnectScriptMessage(script unsafe.Pointer, handler uintptr) {
	C.disconnect_script_message((*C.FridaScript)(script), C.gulong(handler))
}
