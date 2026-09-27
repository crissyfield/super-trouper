package frida

/*
#include <frida-core.h>
*/
import "C"

// ApplicationScope specifies the detail level returned for applications.
type ApplicationScope string

// Application scopes supported by Frida.
const (
	// ApplicationScopeMinimal includes basic application information only.
	ApplicationScopeMinimal ApplicationScope = "minimal"

	// ApplicationScopeMetadata includes application metadata.
	ApplicationScopeMetadata ApplicationScope = "metadata"

	// ApplicationScopeFull includes all available application details.
	ApplicationScopeFull ApplicationScope = "full"
)

// applicationScopeToFrida converts a Go ApplicationScope to a C.FridaScope, reporting whether the scope is
// valid.
func applicationScopeToFrida(scope ApplicationScope) (C.FridaScope, bool) {
	switch scope {
	case ApplicationScopeMinimal:
		// Minimal information
		return C.FRIDA_SCOPE_MINIMAL, true
	case ApplicationScopeMetadata:
		// Application metadata
		return C.FRIDA_SCOPE_METADATA, true
	case ApplicationScopeFull:
		// All available details
		return C.FRIDA_SCOPE_FULL, true
	default:
		// Invalid scope
		return 0, false
	}
}
