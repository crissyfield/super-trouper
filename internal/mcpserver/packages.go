package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// addPackagesTools registers the package tools.
func (s *MCPServer) addPackagesTools() {
	// Install a package
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "package_install",
		Description: "Installs an npm package into Super Trouper's shared Frida workspace. Import it by name " +
			"from script_create source; use the bridges input for the built-in ObjC, Java, and Swift globals.",
	}, s.packageInstall)

	// List installed packages
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "package_list",
		Description: "Lists direct npm packages in Super Trouper's shared Frida workspace.",
	}, s.packageList)
}

// packageInstallInput contains the input arguments of the 'package_install' tool.
type packageInstallInput struct {
	Name    string `json:"name" jsonschema:"npm package name to install"`
	Version string `json:"version,omitempty" jsonschema:"npm version, tag, or semver range; omit for the registry default"`
}

// packageInstallOutput contains the output of the 'package_install' tool.
type packageInstallOutput struct{}

// packageInstall implements the 'package_install' tool.
func (s *MCPServer) packageInstall(ctx context.Context, _ *mcp.CallToolRequest, in packageInstallInput) (*mcp.CallToolResult, packageInstallOutput, error) {
	// Get package manager
	pm, err := s.manager.PackageManager()
	if err != nil {
		return nil, packageInstallOutput{}, fmt.Errorf("get package manager: %w", err)
	}

	// Install package
	err = pm.InstallPackages(ctx, frida.WithInstallPackageWithNameAndVersion(in.Name, in.Version))
	if err != nil {
		return nil, packageInstallOutput{}, fmt.Errorf("install package: %w", err)
	}

	return nil, packageInstallOutput{}, nil
}

// packageListInput contains the input arguments of the 'package_list' tool.
type packageListInput struct{}

// packageEntry describes an npm package in the shared workspace.
type packageEntry struct {
	Name    string `json:"name" jsonschema:"npm package name"`
	Version string `json:"version" jsonschema:"resolved package version, or the declared version constraint when no lockfile entry exists"`
}

// packageListOutput contains the output of the 'package_list' tool.
type packageListOutput struct {
	Packages []packageEntry `json:"packages" jsonschema:"direct npm packages in the shared workspace"`
}

// packageList implements the 'package_list' tool.
func (s *MCPServer) packageList(_ context.Context, _ *mcp.CallToolRequest, _ packageListInput) (*mcp.CallToolResult, packageListOutput, error) {
	// Get package manager
	pm, err := s.manager.PackageManager()
	if err != nil {
		return nil, packageListOutput{}, fmt.Errorf("get package manager: %w", err)
	}

	// List packages
	packages, err := pm.ListPackages()
	if err != nil {
		return nil, packageListOutput{}, fmt.Errorf("list packages: %w", err)
	}

	// Collect package entries
	entries := make([]packageEntry, len(packages))

	for i, pkg := range packages {
		entries[i] = packageEntry{
			Name:    pkg.Name,
			Version: pkg.Version,
		}
	}

	return nil, packageListOutput{Packages: entries}, nil
}
