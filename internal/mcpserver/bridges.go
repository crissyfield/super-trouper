package mcpserver

import (
	"fmt"
	"maps"
	"slices"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// bridgeEntry couples a bridge's package information with its description.
type bridgeEntry struct {
	packageInfo frida.PackageInfo
	description string
}

// supportedBridges maps valid bridge names to their package information, global export, and description.
var supportedBridges = map[string]bridgeEntry{
	"objc": {
		description: "Objective-C runtime bridge, exposing the `ObjC` global. For iOS and macOS targets.",
		packageInfo: frida.PackageInfo{Name: "frida-objc-bridge", Export: "ObjC"},
	},
	"java": {
		description: "Java runtime bridge, exposing the `Java` global. For Android and other JVM targets.",
		packageInfo: frida.PackageInfo{Name: "frida-java-bridge", Export: "Java"},
	},
	"swift": {
		description: "Swift runtime bridge, exposing the `Swift` global.",
		packageInfo: frida.PackageInfo{Name: "frida-swift-bridge", Export: "Swift"},
	},
}

// validateBridges validates the given bridge names, rejecting duplicates and unknown names, and returns the
// package information of the selected bridges in input order.
func validateBridges(names []string) ([]frida.PackageInfo, error) {
	// Collect duplicates and package infos
	duplicates := make(map[string]bool, len(names))
	packageInfos := make([]frida.PackageInfo, 0, len(names))

	for _, name := range names {
		// Check for duplicates
		if duplicates[name] {
			return nil, fmt.Errorf("duplicate bridge [bridge=%s]", name)
		}

		duplicates[name] = true

		// Look up bridge info
		entry, ok := supportedBridges[name]
		if !ok {
			return nil, fmt.Errorf("unknown bridge [bridge=%s]", name)
		}

		packageInfos = append(packageInfos, entry.packageInfo)
	}

	return packageInfos, nil
}

// allBridgePackages returns the package information of all supported bridges in sorted order.
func allBridgePackages() []frida.PackageInfo {
	// Collect package infos
	packageInfos := make([]frida.PackageInfo, 0, len(supportedBridges))

	for _, name := range slices.Sorted(maps.Keys(supportedBridges)) {
		packageInfos = append(packageInfos, supportedBridges[name].packageInfo)
	}

	return packageInfos
}
