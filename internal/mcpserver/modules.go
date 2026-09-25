package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/valyala/fasttemplate"
)

const (
	defaultModuleListLimit = 64        // Default number of modules to return.
	maxModuleListLimit     = 500       // Maximum number of modules to return.
	moduleDetailSummary    = "summary" // Summary module details.
	moduleDetailFull       = "full"    // Full module details.
)

// addModulesTools registers the module tools.
func (s *MCPServer) addModulesTools() {
	// List loaded modules
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "module_list",
		Description: "Lists the modules loaded in an attached process. Results can be matched by name or " +
			"path and paginated.",
	}, s.moduleList)
}

// moduleListTemplate enumerates, filters, and paginates modules in the target process.
var moduleListTemplate = fasttemplate.New(
	`
		(() => {
			const modules = Process.enumerateModules();
			const match = {{match}};
			const matched = match === "" ? modules : modules.filter(module =>
				module.name.toLowerCase().includes(match) || module.path.toLowerCase().includes(match));
			const offset = {{offset}};
			const end = Math.min(offset + {{limit}}, matched.length);
			const page = matched.slice(offset, end);
			const full = {{full}};

			return {
				total: modules.length,
				matched: matched.length,
				offset,
				returned: page.length,
				truncated: end < matched.length,
				modules: page.map(module => full ? {
					name: module.name,
					base: module.base.toString(),
					size: module.size,
					path: module.path
				} : {
					name: module.name,
					base: module.base.toString()
				})
			};
		})()
	`,
	"{{",
	"}}",
)

// moduleInfo describes a loaded module.
type moduleInfo struct {
	Name string  `json:"name" jsonschema:"canonical module name"`
	Base string  `json:"base" jsonschema:"module base address as a hexadecimal string"`
	Size *uint64 `json:"size,omitempty" jsonschema:"module size in bytes, included with full detail"`
	Path *string `json:"path,omitempty" jsonschema:"module filesystem path, included with full detail"`
}

// moduleListInput contains the input arguments of the 'module_list' tool.
type moduleListInput struct {
	Session string `json:"session" jsonschema:"handle of the session to list modules in"`
	Match   string `json:"match,omitempty" jsonschema:"case-insensitive substring to match against module names and paths"`
	Offset  int    `json:"offset,omitempty" jsonschema:"number of matching modules to skip (default 0)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"maximum number of matching modules to return (1-500, default 64)"`
	Detail  string `json:"detail,omitempty" jsonschema:"module detail level: 'summary' (default) or 'full'"`
}

// moduleListOutput contains the output of the 'module_list' tool.
type moduleListOutput struct {
	Total     int          `json:"total" jsonschema:"number of modules loaded in the process before matching"`
	Matched   int          `json:"matched" jsonschema:"number of modules matching the requested filter"`
	Offset    int          `json:"offset" jsonschema:"number of matching modules skipped"`
	Returned  int          `json:"returned" jsonschema:"number of modules returned"`
	Truncated bool         `json:"truncated" jsonschema:"whether additional matching modules are available"`
	Modules   []moduleInfo `json:"modules" jsonschema:"matching loaded modules"`
}

// moduleList implements the 'module_list' tool.
func (s *MCPServer) moduleList(ctx context.Context, _ *mcp.CallToolRequest, in moduleListInput) (*mcp.CallToolResult, moduleListOutput, error) {
	// Validate pagination
	if in.Offset < 0 {
		return nil, moduleListOutput{}, errors.New("offset must not be negative")
	}

	limit := in.Limit

	if limit == 0 {
		limit = defaultModuleListLimit
	}

	if (limit < 1) || (limit > maxModuleListLimit) {
		return nil, moduleListOutput{}, fmt.Errorf("limit must be between 1 and %d", maxModuleListLimit)
	}

	// Validate detail level
	detail := strings.ToLower(in.Detail)

	if detail == "" {
		detail = moduleDetailSummary
	}

	if (detail != moduleDetailSummary) && (detail != moduleDetailFull) {
		return nil, moduleListOutput{}, fmt.Errorf("invalid detail [detail=%s]", in.Detail)
	}

	// Encode match string
	match, err := json.Marshal(strings.ToLower(in.Match))
	if err != nil {
		return nil, moduleListOutput{}, fmt.Errorf("encode match: %w", err)
	}

	// Enumerate, filter, and paginate modules
	evaluator, err := s.sessionEvaluator(ctx, in.Session)
	if err != nil {
		return nil, moduleListOutput{}, err
	}

	output, err := evaluator.Evaluate[moduleListOutput](
		ctx,
		moduleListTemplate.ExecuteString(map[string]any{
			"match":  match,
			"offset": strconv.Itoa(in.Offset),
			"limit":  strconv.Itoa(limit),
			"full":   strconv.FormatBool(detail == moduleDetailFull),
		}),
	)

	if err != nil {
		return nil, moduleListOutput{}, fmt.Errorf("enumerate modules: %w", err)
	}

	return nil, output, nil
}
