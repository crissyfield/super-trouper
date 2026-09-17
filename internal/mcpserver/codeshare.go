package mcpserver

import (
	"context"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/codeshare"
)

// addCodeShareTools registers the CodeShare tools.
func (s *MCPServer) addCodeShareTools() {
	// Search CodeShare projects
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "codeshare_search",
		Description: "Searches Frida CodeShare (https://codeshare.frida.re) for projects matching the given query.",
	}, s.codeShareSearch)

	// List popular CodeShare projects
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "codeshare_popular",
		Description: "Lists the most popular projects on Frida CodeShare (https://codeshare.frida.re).",
	}, s.codeSharePopular)

	// Get a CodeShare project
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "codeshare_project",
		Description: "Returns a project from Frida CodeShare (https://codeshare.frida.re), including its JavaScript " +
			"source, which can be run with the other scripting tools.",
	}, s.codeShareProject)
}

// codeShareSearchInput contains the input arguments of the 'codeshare_search' tool.
type codeShareSearchInput struct {
	Query string `json:"query" jsonschema:"query, matched against project names, descriptions, and source code"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of projects to return (default 10)"`
}

// codeShareSearchOutput contains the output of the 'codeshare_search' tool.
type codeShareSearchOutput struct {
	Projects []codeshare.Project `json:"projects" jsonschema:"the matching CodeShare projects"`
}

// codeShareSearch implements the 'codeshare_search' tool.
func (s *MCPServer) codeShareSearch(ctx context.Context, _ *mcp.CallToolRequest, in codeShareSearchInput) (*mcp.CallToolResult, codeShareSearchOutput, error) {
	// Assemble search options
	var options []codeshare.SearchOption

	if in.Limit > 0 {
		options = append(options, codeshare.WithSearchLimit(in.Limit))
	}

	// Search CodeShare
	projects, err := s.codeshare.Search(ctx, in.Query, options...)
	if err != nil {
		return nil, codeShareSearchOutput{}, fmt.Errorf("search CodeShare: %w", err)
	}

	return nil, codeShareSearchOutput{Projects: projects}, nil
}

// codeSharePopularInput contains the input arguments of the 'codeshare_popular' tool.
type codeSharePopularInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of projects to return (default 10)"`
}

// codeSharePopularOutput contains the output of the 'codeshare_popular' tool.
type codeSharePopularOutput struct {
	Projects []codeshare.Project `json:"projects" jsonschema:"the most popular CodeShare projects"`
}

// codeSharePopular implements the 'codeshare_popular' tool.
func (s *MCPServer) codeSharePopular(ctx context.Context, _ *mcp.CallToolRequest, in codeSharePopularInput) (*mcp.CallToolResult, codeSharePopularOutput, error) {
	// Assemble popular options
	var options []codeshare.PopularOption

	if in.Limit > 0 {
		options = append(options, codeshare.WithPopularLimit(in.Limit))
	}

	// List popular CodeShare projects
	projects, err := s.codeshare.Popular(ctx, options...)
	if err != nil {
		return nil, codeSharePopularOutput{}, fmt.Errorf("list popular CodeShare projects: %w", err)
	}

	return nil, codeSharePopularOutput{Projects: projects}, nil
}

// codeShareProjectInput contains the input arguments of the 'codeshare_project' tool.
type codeShareProjectInput struct {
	Owner string `json:"owner" jsonschema:"nickname of the project owner, as returned by codeshare_search and codeshare_popular"`
	Slug  string `json:"slug" jsonschema:"slug of the project, as returned by codeshare_search and codeshare_popular"`
}

// codeShareProjectOutput contains the output of the 'codeshare_project' tool.
type codeShareProjectOutput struct {
	Project codeshare.Project `json:"project" jsonschema:"the requested CodeShare project"`
}

// codeShareProject implements the 'codeshare_project' tool.
func (s *MCPServer) codeShareProject(ctx context.Context, _ *mcp.CallToolRequest, in codeShareProjectInput) (*mcp.CallToolResult, codeShareProjectOutput, error) {
	// Fetch project
	project, err := s.codeshare.Project(ctx, in.Owner, in.Slug)
	if (err != nil) && errors.Is(err, codeshare.ErrNotFound) {
		return nil, codeShareProjectOutput{}, fmt.Errorf("project not found [owner=%s, slug=%s]", in.Owner, in.Slug)
	}
	if err != nil {
		return nil, codeShareProjectOutput{}, fmt.Errorf("fetch CodeShare project: %w", err)
	}

	return nil, codeShareProjectOutput{Project: project}, nil
}
