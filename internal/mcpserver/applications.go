package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// appInfo describes an application on a Frida device.
type appInfo struct {
	Identifier string `json:"identifier"` // Application bundle identifier.
	Name       string `json:"name"`       // Application name.
	PID        uint   `json:"pid"`        // Running process ID.
	Running    bool   `json:"running"`    // Whether the application is running.
}

// addApplicationsTools registers the application tools.
func (s *MCPServer) addApplicationsTools() {
	// List installed applications
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "app_list",
		Description: "Lists the applications installed on a Frida device.",
	}, s.appList)

	// Find an application
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "app_find",
		Description: "Finds an application on a Frida device by identifier or name.",
	}, s.appFind)

	// Query the frontmost application
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "app_frontmost",
		Description: "Returns the frontmost application on a Frida device.",
	}, s.appFrontmost)
}

// appListInput contains the input arguments of the 'app_list' tool.
type appListInput struct {
	Device      string   `json:"device" jsonschema:"handle of the device to list the applications of"`
	Identifiers []string `json:"identifiers,omitempty" jsonschema:"only return applications with one of these bundle identifiers"`
	Names       []string `json:"names,omitempty" jsonschema:"only return applications with one of these names"`
}

// appListOutput contains the output of the 'app_list' tool.
type appListOutput struct {
	Applications []appInfo `json:"applications" jsonschema:"the applications installed on the device"`
}

// appList implements the 'app_list' tool.
func (s *MCPServer) appList(ctx context.Context, _ *mcp.CallToolRequest, in appListInput) (*mcp.CallToolResult, appListOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, appListOutput{}, err
	}

	// Assemble list options
	var options []frida.ApplicationOption

	if len(in.Identifiers) != 0 {
		options = append(options, frida.WithApplicationIdentifiers(in.Identifiers...))
	}

	if len(in.Names) != 0 {
		options = append(options, frida.WithApplicationNames(in.Names...))
	}

	// List applications
	apps, err := state.device.ListApplications(ctx, options...)
	if err != nil {
		return nil, appListOutput{}, fmt.Errorf("list applications: %w", err)
	}

	// Collect application information
	appInfos := make([]appInfo, len(apps))

	for i, app := range apps {
		appInfos[i] = appInfo{
			Identifier: app.Identifier,
			Name:       app.Name,
			PID:        app.PID,
			Running:    app.Running,
		}
	}

	return nil, appListOutput{Applications: appInfos}, nil
}

// appFindInput contains the input arguments of the 'app_find' tool.
type appFindInput struct {
	Device     string `json:"device" jsonschema:"handle of the device to search"`
	Identifier string `json:"identifier,omitempty" jsonschema:"bundle identifier of the application to find"`
	Name       string `json:"name,omitempty" jsonschema:"name of the application to find"`
}

// appFindOutput contains the output of the 'app_find' tool.
type appFindOutput struct {
	Application appInfo `json:"application" jsonschema:"the application found on the device"`
}

// appFind implements the 'app_find' tool.
func (s *MCPServer) appFind(ctx context.Context, _ *mcp.CallToolRequest, in appFindInput) (*mcp.CallToolResult, appFindOutput, error) {
	// Validate input
	if (in.Identifier != "") == (in.Name != "") {
		return nil, appFindOutput{}, errors.New("either application identifier or name must be given")
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, appFindOutput{}, err
	}

	// Find application
	var app *frida.Application

	switch {
	case in.Identifier != "":
		// Find application by identifier
		app, err = state.device.FindApplicationByIdentifier(ctx, in.Identifier)
		if err != nil {
			return nil, appFindOutput{}, fmt.Errorf("find application: %w", err)
		}

		if app == nil {
			return nil, appFindOutput{}, fmt.Errorf("application not found [identifier=%s]", in.Identifier)
		}

	default:
		// Find application by name
		app, err = state.device.FindApplicationByName(ctx, in.Name)
		if err != nil {
			return nil, appFindOutput{}, fmt.Errorf("find application: %w", err)
		}

		if app == nil {
			return nil, appFindOutput{}, fmt.Errorf("application not found [name=%s]", in.Name)
		}
	}

	// Return application information
	return nil, appFindOutput{Application: appInfo{
		Identifier: app.Identifier,
		Name:       app.Name,
		PID:        app.PID,
		Running:    app.Running,
	}}, nil
}

// appFrontmostInput contains the input arguments of the 'app_frontmost' tool.
type appFrontmostInput struct {
	Device string `json:"device" jsonschema:"handle of the device to query"`
}

// appFrontmostOutput contains the output of the 'app_frontmost' tool.
type appFrontmostOutput struct {
	Application appInfo `json:"application" jsonschema:"the frontmost application on the device"`
}

// appFrontmost implements the 'app_frontmost' tool.
func (s *MCPServer) appFrontmost(ctx context.Context, _ *mcp.CallToolRequest, in appFrontmostInput) (*mcp.CallToolResult, appFrontmostOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, appFrontmostOutput{}, err
	}

	// Query frontmost application
	app, err := state.device.FrontmostApplication(ctx)
	if err != nil {
		return nil, appFrontmostOutput{}, fmt.Errorf("query frontmost application: %w", err)
	}

	if app == nil {
		return nil, appFrontmostOutput{}, errors.New("no frontmost application on device")
	}

	return nil, appFrontmostOutput{Application: appInfo{
		Identifier: app.Identifier,
		Name:       app.Name,
		PID:        app.PID,
		Running:    app.Running,
	}}, nil
}
