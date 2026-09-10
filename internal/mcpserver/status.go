package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

const (
	// fridaDocumentationURL is the URL of the Frida JavaScript API documentation.
	fridaDocumentationURL = "https://frida.re/docs/javascript-api/"

	// fridaVersionedAPISourceURL is the URL of the version-matched Frida GumJS source.
	fridaVersionedAPISourceURL = "https://github.com/frida/frida-gum/tree/%s/bindings/gumjs"
)

// addStatusTools registers the Frida status tools.
func (s *MCPServer) addStatusTools() {
	// Return Frida version
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "frida_version",
		Description: "Returns the version of the linked Frida Core library.",
	}, s.fridaVersion)

	// Return Frida documentation
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "frida_documentation",
		Description: "Returns documentation links for the Frida JavaScript API.",
	}, s.fridaDocumentation)
}

// fridaVersionInput contains the input arguments of the 'frida_version' tool.
type fridaVersionInput struct{}

// fridaVersionOutput contains the output of the 'frida_version' tool.
type fridaVersionOutput struct {
	Version string `json:"version" jsonschema:"the version of the linked Frida Core library"`
}

// fridaVersion implements the 'frida_version' tool.
func (*MCPServer) fridaVersion(_ context.Context, _ *mcp.CallToolRequest, _ fridaVersionInput) (*mcp.CallToolResult, fridaVersionOutput, error) {
	return nil, fridaVersionOutput{Version: frida.Version()}, nil
}

// fridaDocumentationInput contains the input arguments of the 'frida_documentation' tool.
type fridaDocumentationInput struct{}

// fridaDocumentationOutput contains the output of the 'frida_documentation' tool.
type fridaDocumentationOutput struct {
	DocumentationURL      string `json:"documentation_url" jsonschema:"URL of the current Frida JavaScript API reference"`
	VersionedAPISourceURL string `json:"versioned_api_source_url" jsonschema:"URL of the version-matched Frida GumJS source"`
}

// fridaDocumentation implements the 'frida_documentation' tool.
func (*MCPServer) fridaDocumentation(_ context.Context, _ *mcp.CallToolRequest, _ fridaDocumentationInput) (*mcp.CallToolResult, fridaDocumentationOutput, error) {
	return nil, fridaDocumentationOutput{
		DocumentationURL:      fridaDocumentationURL,
		VersionedAPISourceURL: fmt.Sprintf(fridaVersionedAPISourceURL, frida.Version()),
	}, nil
}
