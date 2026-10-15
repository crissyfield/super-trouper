package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"uuid"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

const (
	defaultPatternDecodeCount = 4096
	maxPatternDecodeCount     = 1024 * 1024
	patternProjectsDirectory  = "patterns"
)

// patternProject is the persisted metadata for one managed Pattern project.
type patternProject struct {
	Handle     string   `json:"handle"`     // Unique handle, matching the project directory name.
	Name       string   `json:"name"`       // Human-readable project name.
	Entrypoint string   `json:"entrypoint"` // Relative Pattern entrypoint path.
	Files      []string `json:"files"`      // Relative Pattern source paths.
}

// patternState contains the mutable state of a managed Pattern project. All access to a state, its project, and
// its modules must happen while holding the mutex of the containing MCPServer.
type patternState struct {
	project patternProject                  // Persisted project metadata.
	modules map[string]*frida.PatternModule // Modules keyed by target platform and architecture.
}

// addPatternsTools registers the Pattern project and decoding tools.
func (s *MCPServer) addPatternsTools() {
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "pattern_create",
		Description: "Creates a managed Frida Pattern project from .hexpat or .pat source files. Use " +
			"pattern_describe to validate it for a target.",
	}, s.patternCreate)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "pattern_delete",
		Description: "Deletes a managed Frida Pattern project and releases its compiled modules.",
	}, s.patternDelete)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "pattern_list",
		Description: "Lists managed Frida Pattern projects.",
	}, s.patternList)

	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "pattern_read",
		Description: "Returns one source file from a managed Frida Pattern project.",
	}, s.patternRead)

	mcp.AddTool(s.server, &mcp.Tool{
		Name: "pattern_describe",
		Description: "Compiles a Pattern project for an attached target and returns diagnostics, types, and " +
			"external inputs. Use this before pattern_decode.",
	}, s.patternDescribe)

	mcp.AddTool(s.server, &mcp.Tool{
		Name: "pattern_decode",
		Description: "Reads up to 1 MiB of memory from an attached process and decodes the snapshot with a " +
			"managed Frida Pattern project. Decoding runs on the host and does not dereference target " +
			"pointers automatically.",
	}, s.patternDecode)
}

// lookupPatternState returns a Pattern project state. The caller must hold s.mu.
func (s *MCPServer) lookupPatternState(handle string) (*patternState, error) {
	if s.closed {
		return nil, errMCPServerClosed
	}

	state, ok := s.patterns[handle]
	if !ok {
		return nil, fmt.Errorf("unknown Pattern handle [handle=%s]", handle)
	}

	return state, nil
}

// patternSourceInput is a single Pattern source file in the input arguments of a tool call.
type patternSourceInput struct {
	Path   string `json:"path" jsonschema:"relative .hexpat or .pat source path"`
	Source string `json:"source" jsonschema:"Pattern source code"`
}

// patternCreateInput contains the input arguments of the 'pattern_create' tool.
type patternCreateInput struct {
	Name       string               `json:"name" jsonschema:"human-readable Pattern project name"`
	Entrypoint string               `json:"entrypoint" jsonschema:"relative source file to compile"`
	Files      []patternSourceInput `json:"files" jsonschema:"Pattern source files"`
}

// patternCreateOutput contains the output of the 'pattern_create' tool.
type patternCreateOutput struct {
	Pattern string `json:"pattern" jsonschema:"handle of the created Pattern project"`
}

// patternCreate implements the 'pattern_create' tool.
func (s *MCPServer) patternCreate(_ context.Context, _ *mcp.CallToolRequest, in patternCreateInput) (*mcp.CallToolResult, patternCreateOutput, error) {
	// Validate input
	if len(in.Files) == 0 {
		return nil, patternCreateOutput{}, errors.New("at least one Pattern source file is required")
	}

	// Collect source files
	files := make(map[string]string, len(in.Files))

	for _, file := range in.Files {
		if err := validatePatternPath(file.Path); err != nil {
			return nil, patternCreateOutput{}, fmt.Errorf("invalid Pattern source path [path=%s]: %w", file.Path, err)
		}

		if _, exists := files[file.Path]; exists {
			return nil, patternCreateOutput{}, fmt.Errorf("duplicate Pattern source path [path=%s]", file.Path)
		}

		files[file.Path] = file.Source
	}

	// Validate project
	project := patternProject{
		Handle:     uuid.New().String(),
		Name:       strings.TrimSpace(in.Name),
		Entrypoint: in.Entrypoint,
		Files:      slices.Sorted(maps.Keys(files)),
	}

	err := validatePatternProject(project, files)
	if err != nil {
		return nil, patternCreateOutput{}, fmt.Errorf("validate Pattern project: %w", err)
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if server is already closed
	if s.closed {
		return nil, patternCreateOutput{}, errMCPServerClosed
	}

	// Create Pattern project root
	root := filepath.Join(s.workspace, patternProjectsDirectory)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, patternCreateOutput{}, fmt.Errorf("create Pattern project root: %w", err)
	}

	// Write project into a temporary directory
	temporary, err := os.MkdirTemp(root, ".pattern-")
	if err != nil {
		return nil, patternCreateOutput{}, fmt.Errorf("create temporary Pattern project: %w", err)
	}

	defer os.RemoveAll(temporary) //nolint

	// Write manifest
	manifest, err := json.Marshal(project)
	if err != nil {
		return nil, patternCreateOutput{}, fmt.Errorf("encode Pattern manifest: %w", err)
	}

	err = os.WriteFile(filepath.Join(temporary, "manifest.json"), manifest, 0o600)
	if err != nil {
		return nil, patternCreateOutput{}, fmt.Errorf("write Pattern manifest: %w", err)
	}

	// Write source files
	for name, source := range files {
		// Assemble path
		path := filepath.Join(temporary, name)

		// Create parent directory
		err := os.MkdirAll(filepath.Dir(path), 0o700)
		if err != nil {
			return nil, patternCreateOutput{}, fmt.Errorf("create Pattern source directory: %w", err)
		}

		// Write pattern source
		err = os.WriteFile(path, []byte(source), 0o600)
		if err != nil {
			return nil, patternCreateOutput{}, fmt.Errorf("write Pattern source [path=%s]: %w", name, err)
		}
	}

	// Move the project into place
	err = os.Rename(
		temporary,
		filepath.Join(s.workspace, patternProjectsDirectory, project.Handle),
	)

	if err != nil {
		return nil, patternCreateOutput{}, fmt.Errorf("replace Pattern project: %w", err)
	}

	// Register project
	s.patterns[project.Handle] = &patternState{
		project: project,
		modules: make(map[string]*frida.PatternModule),
	}

	return nil, patternCreateOutput{Pattern: project.Handle}, nil
}

// patternDeleteInput contains the input arguments of the 'pattern_delete' tool.
type patternDeleteInput struct {
	Pattern string `json:"pattern" jsonschema:"handle of the Pattern project"`
}

// patternDeleteOutput contains the output of the 'pattern_delete' tool.
type patternDeleteOutput struct{}

// patternDelete implements the 'pattern_delete' tool.
func (s *MCPServer) patternDelete(_ context.Context, _ *mcp.CallToolRequest, in patternDeleteInput) (*mcp.CallToolResult, patternDeleteOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up project
	state, err := s.lookupPatternState(in.Pattern)
	if err != nil {
		return nil, patternDeleteOutput{}, err
	}

	// Remove project from state
	delete(s.patterns, in.Pattern)

	// Release compiled modules
	for _, module := range state.modules {
		module.Close()
	}

	// Delete project directory
	err = os.RemoveAll(
		filepath.Join(s.workspace, patternProjectsDirectory, state.project.Handle),
	)

	if err != nil {
		return nil, patternDeleteOutput{}, fmt.Errorf("delete Pattern project: %w", err)
	}

	return nil, patternDeleteOutput{}, nil
}

// patternSummary is a summary of a managed Pattern project returned by the 'pattern_list' tool.
type patternSummary struct {
	Pattern    string   `json:"pattern" jsonschema:"handle of the Pattern project"`
	Name       string   `json:"name" jsonschema:"human-readable Pattern project name"`
	Entrypoint string   `json:"entrypoint" jsonschema:"relative Pattern entrypoint path"`
	Files      []string `json:"files" jsonschema:"relative Pattern source paths"`
}

// patternListInput contains the input arguments of the 'pattern_list' tool.
type patternListInput struct{}

// patternListOutput contains the output of the 'pattern_list' tool.
type patternListOutput struct {
	Patterns []patternSummary `json:"patterns" jsonschema:"managed Pattern projects"`
}

// patternList implements the 'pattern_list' tool.
func (s *MCPServer) patternList(_ context.Context, _ *mcp.CallToolRequest, _ patternListInput) (*mcp.CallToolResult, patternListOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if server is already closed
	if s.closed {
		return nil, patternListOutput{}, errMCPServerClosed
	}

	// Collect project summaries
	values := make([]patternSummary, 0, len(s.patterns))

	for _, state := range s.patterns {
		values = append(values, patternSummary{
			Pattern:    state.project.Handle,
			Name:       state.project.Name,
			Entrypoint: state.project.Entrypoint,
			Files:      slices.Clone(state.project.Files),
		})
	}

	// Sort summaries by name
	slices.SortFunc(values, func(a patternSummary, b patternSummary) int {
		return strings.Compare(a.Name, b.Name)
	})

	return nil, patternListOutput{Patterns: values}, nil
}

// patternReadInput contains the input arguments of the 'pattern_read' tool.
type patternReadInput struct {
	Pattern string `json:"pattern" jsonschema:"handle of the Pattern project"`
	Path    string `json:"path" jsonschema:"relative Pattern source path to read"`
}

// patternReadOutput contains the output of the 'pattern_read' tool.
type patternReadOutput struct {
	Source string `json:"source" jsonschema:"Pattern source code"`
}

// patternRead implements the 'pattern_read' tool.
func (s *MCPServer) patternRead(_ context.Context, _ *mcp.CallToolRequest, in patternReadInput) (*mcp.CallToolResult, patternReadOutput, error) {
	// Validate path
	err := validatePatternPath(in.Path)
	if err != nil {
		return nil, patternReadOutput{}, fmt.Errorf("validate Pattern source path: %w", err)
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up project
	state, err := s.lookupPatternState(in.Pattern)
	if err != nil {
		return nil, patternReadOutput{}, err
	}

	// Check that the source belongs to the project
	if !slices.Contains(state.project.Files, in.Path) {
		return nil, patternReadOutput{}, fmt.Errorf("unknown Pattern source [path=%s]", in.Path)
	}

	// Validate file
	err = validatePatternSourceFile(
		filepath.Join(s.workspace, patternProjectsDirectory, state.project.Handle),
		in.Path,
	)

	if err != nil {
		return nil, patternReadOutput{}, fmt.Errorf("validate Pattern source file: %w", err)
	}

	// Read source
	source, err := os.ReadFile(
		filepath.Join(s.workspace, patternProjectsDirectory, state.project.Handle, in.Path),
	)

	if err != nil {
		return nil, patternReadOutput{}, fmt.Errorf("read Pattern source: %w", err)
	}

	return nil, patternReadOutput{Source: string(source)}, nil
}

// patternDescribeInput contains the input arguments of the 'pattern_describe' tool.
type patternDescribeInput struct {
	Pattern string `json:"pattern" jsonschema:"handle of the Pattern project"`
	Session string `json:"session" jsonschema:"handle of the session whose ABI to compile for"`
}

// patternDescribeOutput contains the output of the 'pattern_describe' tool.
type patternDescribeOutput struct {
	Platform    string                     `json:"platform"`            // Target Process.platform.
	Arch        string                     `json:"arch"`                // Target Process.arch.
	RootType    string                     `json:"root_type,omitempty"` // Root type made from top-level placements.
	Types       []*frida.PatternType       `json:"types"`               // Types declared by the Pattern source.
	Inputs      []*frida.PatternInput      `json:"inputs"`              // External Pattern in variables.
	Diagnostics []*frida.PatternDiagnostic `json:"diagnostics"`         // Pattern compiler diagnostics.
}

// patternDescribe implements the 'pattern_describe' tool.
func (s *MCPServer) patternDescribe(ctx context.Context, _ *mcp.CallToolRequest, in patternDescribeInput) (*mcp.CallToolResult, any, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up project
	state, err := s.lookupPatternState(in.Pattern)
	if err != nil {
		return nil, nil, err
	}

	// Resolve session evaluator
	evaluator, err := s.sessionEvaluatorLocked(ctx, in.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve session evaluator: %w", err)
	}

	// Compile project for target ABI
	module, target, err := s.patternModule(ctx, evaluator, state)
	if err != nil {
		return nil, nil, fmt.Errorf("compile Pattern project: %w", err)
	}

	// Return module description
	return nil, patternDescribeOutput{
		Platform:    target.Platform,
		Arch:        target.Arch,
		RootType:    module.RootType(),
		Types:       module.Types(),
		Inputs:      module.Inputs(),
		Diagnostics: module.Diagnostics(),
	}, nil
}

// patternValueOutput is one node in the decoded value tree returned by the 'pattern_decode' tool.
type patternValueOutput struct {
	ID          uint                 `json:"id"`                     // Unique identifier of the node within the decoded tree.
	Name        string               `json:"name"`                   // Field or element name.
	Type        string               `json:"type"`                   // Name of the decoded type.
	Address     string               `json:"address"`                // Absolute target address of the value, in hexadecimal.
	Offset      string               `json:"offset"`                 // Byte offset within the decoded snapshot, in hexadecimal.
	Size        int64                `json:"size"`                   // Size in bytes of the value.
	Value       any                  `json:"value,omitempty"`        // Decoded scalar value, nil for composite values.
	Label       string               `json:"label,omitempty"`        // Presentation label from the source.
	DisplayName string               `json:"display_name,omitempty"` // Display name overriding the field name.
	Formatted   string               `json:"formatted,omitempty"`    // Formatted rendering of the scalar value.
	Comment     string               `json:"comment,omitempty"`      // Comment from the source.
	Color       string               `json:"color,omitempty"`        // Presentation color from the source.
	Hidden      bool                 `json:"hidden,omitempty"`       // Whether the value is hidden from presentation.
	Inlined     bool                 `json:"inlined,omitempty"`      // Whether the value is inlined into its parent.
	Sealed      bool                 `json:"sealed,omitempty"`       // Whether the value cannot be expanded further.
	BitOffset   *int                 `json:"bit_offset,omitempty"`   // Bit offset within the storage unit, for bitfield members.
	Bits        uint                 `json:"bits,omitempty"`         // Bit width, for bitfield members.
	Count       *int64               `json:"count,omitempty"`        // Number of elements, for arrays.
	Fields      []patternValueOutput `json:"fields,omitempty"`       // Child values of struct or union members.
	Elements    []patternValueOutput `json:"elements,omitempty"`     // Child values of array elements.
	Truncated   bool                 `json:"truncated,omitempty"`    // Whether the value's contents were truncated.
	Section     string               `json:"section,omitempty"`      // Memory section identifier containing the value, empty when unknown.
}

// patternDecodeInput contains the input arguments of the 'pattern_decode' tool.
type patternDecodeInput struct {
	Pattern  string                     `json:"pattern" jsonschema:"handle of the Pattern project"`
	Session  string                     `json:"session" jsonschema:"handle of the session to read memory from"`
	Address  string                     `json:"address" jsonschema:"hex address to decode, with or without 0x prefix"`
	Count    uint                       `json:"count,omitempty" jsonschema:"snapshot size in bytes (1-1048576, default 4096)"`
	Type     string                     `json:"type,omitempty" jsonschema:"declared Pattern type to decode, defaulting to the root type"`
	Inputs   map[string]json.RawMessage `json:"inputs,omitempty" jsonschema:"values for Pattern in variables"`
	MaxNodes uint                       `json:"max_nodes,omitempty" jsonschema:"maximum number of value nodes to decode, defaulting to 4096"`
}

// patternDecodeOutput contains the output of the 'pattern_decode' tool.
type patternDecodeOutput struct {
	Count           uint               `json:"count"`            // Number of target bytes decoded.
	Value           patternValueOutput `json:"value"`            // Decoded Pattern value tree.
	OutputTruncated bool               `json:"output_truncated"` // Whether output was capped to keep the MCP response bounded.
}

// patternDecode implements the 'pattern_decode' tool.
func (s *MCPServer) patternDecode(ctx context.Context, _ *mcp.CallToolRequest, in patternDecodeInput) (*mcp.CallToolResult, any, error) {
	// Determine snapshot size
	count := in.Count

	if count == 0 {
		count = defaultPatternDecodeCount
	}

	if count > maxPatternDecodeCount {
		return nil, nil, fmt.Errorf("count must be less or equal to %d", maxPatternDecodeCount)
	}

	// Parse address
	address, err := parseHexAddress(in.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("parse address: %w", err)
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up project
	state, err := s.lookupPatternState(in.Pattern)
	if err != nil {
		return nil, nil, err
	}

	// Resolve session evaluator
	evaluator, err := s.sessionEvaluatorLocked(ctx, in.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve session evaluator: %w", err)
	}

	// Compile project for target ABI
	module, target, err := s.patternModule(ctx, evaluator, state)
	if err != nil {
		return nil, nil, fmt.Errorf("compile Pattern project: %w", err)
	}

	// Reject modules with compilation diagnostics
	if len(module.Diagnostics()) != 0 {
		return nil, nil, errors.New("pattern has compilation diagnostics; use pattern_describe to inspect")
	}

	// Resolve type name
	typeName := in.Type

	if typeName == "" {
		typeName = module.RootType()
	}

	if typeName == "" {
		return nil, nil, errors.New("pattern type required when source has no root type")
	}

	// Check that requested type is declared or is root type
	declared := slices.ContainsFunc(module.Types(), func(t *frida.PatternType) bool {
		return t.Name == typeName
	})

	if !declared && (typeName != module.RootType()) {
		return nil, nil, fmt.Errorf("unknown Pattern type [type=%s]", typeName)
	}

	// Parse external input values
	inputs, err := patternInputsFromJSON(module, target.Arch, in.Inputs)
	if err != nil {
		return nil, nil, fmt.Errorf("parse Pattern inputs: %w", err)
	}

	// Read memory snapshot
	data, err := evaluator.ReadMemory(ctx, address, int(count))
	if err != nil {
		return nil, nil, fmt.Errorf("read Pattern memory: %w", err)
	}

	// Decode snapshot
	var options []frida.PatternDecodeOption

	if in.MaxNodes > 0 {
		options = append(options, frida.WithPatternDecodeMaxNodes(int(in.MaxNodes)))
	}

	value, err := module.Decode(ctx, typeName, data, address, inputs, options...)
	if err != nil {
		return nil, nil, fmt.Errorf("decode Pattern snapshot: %w", err)
	}

	// Convert decoded value tree
	output, truncated := patternValueToOutput(value)

	// Return output
	return nil, patternDecodeOutput{
		Count:           uint(len(data)),
		Value:           output,
		OutputTruncated: truncated,
	}, nil
}

// patternTarget is the platform and architecture of the session a Pattern module is compiled for.
type patternTarget struct {
	Platform string `json:"platform"` // Target Process.platform.
	Arch     string `json:"arch"`     // Target Process.arch.
}

// patternModule returns the lazily compiled module for the ABI of the session behind the given evaluator. The
// caller must hold the mutex and must keep holding it while the returned module is in use.
func (s *MCPServer) patternModule(ctx context.Context, evaluator *frida.Evaluator, state *patternState) (*frida.PatternModule, patternTarget, error) {
	// Determine the target ABI
	target, err := evaluator.Evaluate[patternTarget](
		ctx,
		`
			({ platform: Process.platform, arch: Process.arch })
		`,
	)

	if err != nil {
		return nil, patternTarget{}, fmt.Errorf("get Pattern target ABI: %w", err)
	}

	if (target.Platform == "") || (target.Arch == "") {
		return nil, patternTarget{}, errors.New("get Pattern target ABI: empty platform or architecture")
	}

	// Return cached module
	key := target.Platform + ":" + target.Arch

	if module, ok := state.modules[key]; ok {
		return module, target, nil
	}

	// Get Pattern compiler
	compiler, err := s.manager.PatternCompiler()
	if err != nil {
		return nil, patternTarget{}, fmt.Errorf("get Pattern compiler: %w", err)
	}

	// Compile the project for the target ABI
	module, err := compiler.Compile(
		ctx,
		filepath.Join(s.workspace, patternProjectsDirectory, state.project.Handle, state.project.Entrypoint),
		frida.WithPatternCompileProjectRoot(s.workspace),
		frida.WithPatternCompilePlatform(target.Platform),
		frida.WithPatternCompileArch(target.Arch),
	)

	if err != nil {
		return nil, patternTarget{}, err
	}

	// Cache the compiled module
	state.modules[key] = module

	return module, target, nil
}

// patternInputsFromJSON validates and decodes the supplied input values against the declared Pattern inputs.
func patternInputsFromJSON(module *frida.PatternModule, arch string, supplied map[string]json.RawMessage) (map[string]any, error) {
	// Reject supplied inputs when none are declared
	inputs := module.Inputs()

	if (len(inputs) == 0) && (len(supplied) != 0) {
		return nil, errors.New("pattern does not declare inputs")
	}

	if len(inputs) == 0 {
		return nil, nil
	}

	// Index declared inputs
	declared := make(map[string]*frida.PatternInput, len(inputs))

	for _, input := range inputs {
		declared[input.Name] = input
	}

	// Reject unknown inputs
	for name := range supplied {
		if _, ok := declared[name]; !ok {
			return nil, fmt.Errorf("unknown Pattern input [name=%s]", name)
		}
	}

	// Decode declared inputs
	values := make(map[string]any, len(inputs))

	for _, input := range inputs {
		// get raw value for input
		raw, ok := supplied[input.Name]
		if !ok {
			return nil, fmt.Errorf("missing Pattern input [name=%s]", input.Name)
		}

		// decode raw value into Go value
		value, err := patternInputFromJSON(module, input.TypeRef, arch, raw)
		if err != nil {
			return nil, fmt.Errorf("decode raw Pattern value [name=%s]: %w", input.Name, err)
		}

		values[input.Name] = value
	}

	return values, nil
}

const (
	patternInputString = "string" // String input.
	patternInputBool   = "bool"   // Boolean input.
	patternInputFloat  = "float"  // Floating-point input.
	patternInputInt32  = "int32"  // Signed 32-bit integer input.
	patternInputUint32 = "uint32" // Unsigned 32-bit integer input.
	patternInputInt64  = "int64"  // Signed 64-bit integer input.
	patternInputUint64 = "uint64" // Unsigned 64-bit integer input.
)

// patternInputFromJSON decodes a single raw JSON value into a Go value for the given Pattern type reference.
func patternInputFromJSON(module *frida.PatternModule, reference *frida.PatternTypeRef, arch string, raw json.RawMessage) (any, error) {
	// Determine the input kind
	kind, err := patternInputKind(module, reference, arch)
	if err != nil {
		return nil, err
	}

	// Decode the value according to its kind
	switch kind {
	case patternInputString:
		// Decode value as string
		var value string

		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, errors.New("must be a string")
		}

		return value, nil

	case patternInputBool:
		// Decode value as boolean
		var value bool

		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, errors.New("must be a boolean")
		}

		return value, nil

	default:
		// Decode value as number
		var decoded any

		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()

		err := decoder.Decode(&decoded)
		if err != nil {
			return nil, errors.New("must be a number")
		}

		number, ok := decoded.(json.Number)
		if !ok {
			return nil, errors.New("must be a number")
		}

		switch kind {
		case patternInputFloat:
			// Parse as floating-point number
			parsed, err := number.Float64()
			if (err != nil) || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
				return nil, errors.New("must be a finite number")
			}

			return parsed, nil

		case patternInputInt32:
			// Parse as signed 32-bit integer
			parsed, err := strconv.ParseInt(number.String(), 10, 32)
			if err != nil {
				return nil, errors.New("must be a signed 32-bit integer")
			}

			return int32(parsed), nil

		case patternInputUint32:
			// Parse as unsigned 32-bit integer
			parsed, err := strconv.ParseUint(number.String(), 10, 32)
			if err != nil {
				return nil, errors.New("must be an unsigned 32-bit integer")
			}

			return uint32(parsed), nil

		case patternInputInt64:
			// Parse as signed 64-bit integer
			parsed, err := number.Int64()
			if err != nil {
				return nil, errors.New("must be a signed 64-bit integer")
			}

			return parsed, nil

		case patternInputUint64:
			// Parse as unsigned 64-bit integer
			parsed, err := strconv.ParseUint(number.String(), 10, 64)
			if err != nil {
				return nil, errors.New("must be an unsigned 64-bit integer")
			}

			return parsed, nil

		default:
			// Reject unsupported input kinds
			return nil, fmt.Errorf("unsupported type %s", kind)
		}
	}
}

// patternInputKind maps a Pattern type reference to an input kind, resolving pointer widths and named enum
// types along the way.
func patternInputKind(module *frida.PatternModule, reference *frida.PatternTypeRef, arch string) (string, error) {
	// Treat untyped inputs as strings
	if reference == nil {
		return patternInputString, nil
	}

	// Resolve pointers to an integer kind
	if reference.Kind == "pointer" {
		if reference.Width != nil {
			return patternInputKind(module, reference.Width, arch)
		}

		if arch == "ia32" || arch == "arm" {
			return patternInputUint32, nil
		}

		return patternInputUint64, nil
	}

	// Resolve named types to their enum underlying type
	if reference.Kind == "named" {
		for _, declared := range module.Types() {
			if declared.Name == reference.Name {
				if declared.Kind != "enum" {
					return "", fmt.Errorf("unsupported named input type %s", reference.Name)
				}

				return patternInputKind(module, declared.Underlying, arch)
			}
		}

		return "", fmt.Errorf("unknown named input type %s", reference.Name)
	}

	// Map scalar type names to input kinds
	switch strings.ToLower(reference.Name) {
	case "bool":
		return patternInputBool, nil
	case "float", "double":
		return patternInputFloat, nil
	case "s8", "s16", "s32", "int", "i8", "i16", "i32":
		return patternInputInt32, nil
	case "s64", "i64":
		return patternInputInt64, nil
	case "u8", "u16", "u32", "uint", "char", "uchar":
		return patternInputUint32, nil
	case "u64", "uint64":
		return patternInputUint64, nil
	case "string":
		return patternInputString, nil
	default:
		return "", fmt.Errorf("unsupported input type %s", reference.Display)
	}
}

// patternValueToOutput converts a decoded Pattern value into its MCP output representation, reporting whether
// the subtree was capped by the decode budget.
func patternValueToOutput(value *frida.PatternValue) (patternValueOutput, bool) {
	// Stringify integers to preserve their exact value
	var scalar = value.Value

	switch typed := value.Value.(type) {
	case int64:
		// Convert signed 64-bit integer to string
		scalar = strconv.FormatInt(typed, 10)

	case uint64:
		// Convert unsigned 64-bit integer to string
		scalar = strconv.FormatUint(typed, 10)
	}

	// Assemble output node
	result := patternValueOutput{
		ID:          value.ID,
		Name:        value.Name,
		Type:        value.TypeName,
		Address:     fmt.Sprintf("0x%x", value.Address),
		Offset:      fmt.Sprintf("0x%x", value.Offset),
		Size:        value.Size,
		Value:       scalar,
		Label:       value.Label,
		DisplayName: value.DisplayName,
		Formatted:   value.Formatted,
		Comment:     value.Comment,
		Color:       value.Color,
		Hidden:      value.Hidden,
		Inlined:     value.Inlined,
		Sealed:      value.Sealed,
		Bits:        value.Bits,
		Truncated:   value.Truncated,
	}

	// Format optional fields
	if value.BitOffset >= 0 {
		result.BitOffset = &value.BitOffset
	}

	if value.Count >= 0 {
		result.Count = &value.Count
	}

	if value.Section != 0 {
		result.Section = fmt.Sprintf("0x%x", value.Section)
	}

	// Convert children, reporting whether any subtree was capped
	truncated := value.Capped

	for _, field := range value.Fields {
		child, childTruncated := patternValueToOutput(field)

		truncated = truncated || childTruncated
		result.Fields = append(result.Fields, child)
	}

	for _, element := range value.Elements {
		child, childTruncated := patternValueToOutput(element)

		truncated = truncated || childTruncated
		result.Elements = append(result.Elements, child)
	}

	return result, truncated
}

// loadPatternProjects loads valid persisted Pattern projects from the given workspace.
func loadPatternProjects(workspace string) (map[string]*patternState, error) {
	// List project directories
	root := filepath.Join(workspace, patternProjectsDirectory)

	entries, err := os.ReadDir(root)
	if (err != nil) && (!errors.Is(err, os.ErrNotExist)) {
		return nil, fmt.Errorf("read pattern project root: %w", err)
	}

	// Load valid projects
	projects := make(map[string]*patternState)

	for _, entry := range entries {
		// Ignore files
		if !entry.IsDir() {
			continue
		}

		// Read manifest
		dir := filepath.Join(root, entry.Name())

		data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			continue
		}

		// Decode manifest
		var project patternProject

		err = json.Unmarshal(data, &project)
		if err != nil {
			continue
		}

		// Collect declared source paths
		files := make(map[string]string, len(project.Files))

		for _, name := range project.Files {
			files[name] = ""
		}

		// Validate project metadata
		err = validatePatternProject(project, files)
		if err != nil {
			continue
		}

		// Validate source files
		invalid := slices.ContainsFunc(project.Files, func(name string) bool {
			return (validatePatternSourceFile(dir, name) != nil)
		})

		if invalid {
			continue
		}

		// Ignore directories with mismatching handles, such as stale write backups
		if project.Handle != entry.Name() {
			continue
		}

		// Register project
		projects[project.Handle] = &patternState{
			project: project,
			modules: make(map[string]*frida.PatternModule),
		}
	}

	return projects, nil
}

// validatePatternProject validates the metadata of a Pattern project against its set of source paths.
func validatePatternProject(project patternProject, files map[string]string) error {
	// Validate metadata
	if project.Handle == "" {
		return errors.New("pattern handle required")
	}

	if project.Name == "" {
		return errors.New("pattern name required")
	}

	err := validatePatternPath(project.Entrypoint)
	if err != nil {
		return fmt.Errorf("invalid Pattern entrypoint: %w", err)
	}

	// Require the entrypoint to be among the source files
	_, ok := files[project.Entrypoint]
	if !ok {
		return fmt.Errorf("pattern entrypoint not a source file [entrypoint=%s]", project.Entrypoint)
	}

	// Validate source paths
	for name := range files {
		err := validatePatternPath(name)
		if err != nil {
			return fmt.Errorf("invalid Pattern source path [name=%s]: %w", name, err)
		}
	}

	return nil
}

// validatePatternPath validates a relative source path for a Pattern project.
func validatePatternPath(name string) error {
	// Require non-empty, relative, and clean path
	if name == "" {
		return errors.New("path required")
	}

	if filepath.IsAbs(name) {
		return errors.New("path must be relative")
	}

	if filepath.Clean(name) != name {
		return fmt.Errorf("path must be clean [path=%s]", name)
	}

	// Reject paths escaping the project
	if (name == ".") || (name == "..") || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes project [path=%s]", name)
	}

	// Require Pattern source ext
	ext := strings.ToLower(filepath.Ext(name))
	if (ext != ".hexpat") && (ext != ".pat") {
		return fmt.Errorf("path must end in .hexpat or .pat [path=%s]", name)
	}

	return nil
}

// validatePatternSourceFile verifies that every component of the source path exists and is not a symbolic link.
func validatePatternSourceFile(directory string, name string) error {
	// Verify every path component
	path := directory

	for component := range strings.SplitSeq(name, string(filepath.Separator)) {
		// Assemble path
		path = filepath.Join(path, component)

		// Get path info
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("get path info [path=%s]: %w", name, err)
		}

		// Reject symbolic links
		symlink := (info.Mode() & os.ModeSymlink) != 0
		if symlink {
			return fmt.Errorf("pattern source must not be a symbolic link [path=%s]", name)
		}
	}

	return nil
}
