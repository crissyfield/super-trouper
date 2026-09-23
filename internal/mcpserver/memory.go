package mcpserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// addMemoryTools registers the memory tools.
func (s *MCPServer) addMemoryTools() {
	// Read memory
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "memory_read",
		Description: "Reads up to 4096 bytes of memory in an attached process and returns it as hex, UTF-8, " +
			"or a NUL-terminated C string. Fails if any byte of the range cannot be read.",
	}, s.memoryRead)

	// Write memory
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "memory_write",
		Description: "Writes up to 4096 bytes of memory in an attached process, given as a hex string. Fails " +
			"if the memory cannot be written; code pages are typically write-protected, so patching code is " +
			"out of scope.",
	}, s.memoryWrite)
}

// parseHexAddress parses a hex address with an optional 0x prefix.
func parseHexAddress(address string) (uint64, error) {
	// Parse address
	lowered := strings.ToLower(strings.TrimSpace(address))
	trimmed := strings.TrimPrefix(lowered, "0x")

	parsed, err := strconv.ParseUint(trimmed, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid hex address [address=%s]", address)
	}

	return parsed, nil
}

// memoryReadInput contains the input arguments of the 'memory_read' tool.
type memoryReadInput struct {
	Session string `json:"session" jsonschema:"handle of the session to read memory in"`
	Address string `json:"address" jsonschema:"hex address to read from, with or without 0x prefix"`
	Count   uint   `json:"count,omitempty" jsonschema:"number of bytes to read (1-4096, default 256)"`
	Format  string `json:"format,omitempty" jsonschema:"output format: 'hex' (default), 'utf8', or 'cstring'"`
}

// memoryReadOutput contains the output of the 'memory_read' tool.
type memoryReadOutput struct {
	Data  string `json:"data" jsonschema:"memory contents in the requested format"`
	Count uint   `json:"count" jsonschema:"number of bytes read"`
}

// memoryRead implements the 'memory_read' tool.
func (s *MCPServer) memoryRead(ctx context.Context, _ *mcp.CallToolRequest, in memoryReadInput) (*mcp.CallToolResult, memoryReadOutput, error) {
	// Validate format
	format := strings.ToLower(in.Format)

	if (format != "") && (format != "hex") && (format != "utf8") && (format != "cstring") {
		return nil, memoryReadOutput{}, fmt.Errorf("invalid format [format=%s]", in.Format)
	}

	// Validate count
	count := in.Count

	if count == 0 {
		count = 256
	}

	if count > 4096 {
		return nil, memoryReadOutput{}, errors.New("count must be less or equal to 4096")
	}

	// Validate address
	address, err := parseHexAddress(in.Address)
	if err != nil {
		return nil, memoryReadOutput{}, err
	}

	// Evaluate statement
	encoded, err := s.evaluateInSession[string](
		ctx,
		in.Session,
		fmt.Sprintf(
			`
				(() => {
					const b = new Uint8Array(ptr("0x%x").readByteArray(%d));
					let h = "";
					for (let i = 0; i < b.length; i++) {
						h += b[i].toString(16).padStart(2, "0");
					}
					return h;
				})()
			`,
			address,
			count,
		),
	)

	if err != nil {
		return nil, memoryReadOutput{}, fmt.Errorf("read memory: %w", err)
	}

	// Decode hex string
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, memoryReadOutput{}, fmt.Errorf("decode memory data: %w", err)
	}

	// Format output
	data := encoded

	switch format {
	case "utf8":
		// Return the longest valid UTF-8 string
		for index := 0; index < len(raw); {
			r, size := utf8.DecodeRune(raw[index:])

			if (r == utf8.RuneError) && (size == 1) {
				raw = raw[:index]
				break
			}

			index += size
		}

		data = string(raw)

	case "cstring":
		// Return C-String, up to the first NUL byte
		if nul := bytes.IndexByte(raw, 0x00); nul >= 0 {
			raw = raw[:nul]
		}

		data = strings.ToValidUTF8(string(raw), "\uFFFD")
	}

	return nil, memoryReadOutput{Data: data, Count: uint(len(raw))}, nil
}

// memoryWriteInput contains the input arguments of the 'memory_write' tool.
type memoryWriteInput struct {
	Session string `json:"session" jsonschema:"handle of the session to write memory in"`
	Address string `json:"address" jsonschema:"hex address to write to, with or without 0x prefix"`
	Bytes   string `json:"bytes" jsonschema:"bytes to write as a hex string (even length, up to 8192 characters)"`
}

// memoryWriteOutput contains the output of the 'memory_write' tool.
type memoryWriteOutput struct {
	Written uint `json:"written" jsonschema:"number of bytes written"`
}

// memoryWrite implements the 'memory_write' tool.
func (s *MCPServer) memoryWrite(ctx context.Context, _ *mcp.CallToolRequest, in memoryWriteInput) (*mcp.CallToolResult, memoryWriteOutput, error) {
	// Validate bytes
	if in.Bytes == "" {
		return nil, memoryWriteOutput{}, errors.New("bytes must not be empty")
	}

	if len(in.Bytes) > 8192 {
		return nil, memoryWriteOutput{}, errors.New("bytes must be less or equal to 8192 hex characters")
	}

	if len(in.Bytes)%2 != 0 {
		return nil, memoryWriteOutput{}, errors.New("bytes must have an even number of hex characters")
	}

	if _, err := hex.DecodeString(in.Bytes); err != nil {
		return nil, memoryWriteOutput{}, fmt.Errorf("invalid hex bytes: %w", err)
	}

	// Validate address
	address, err := parseHexAddress(in.Address)
	if err != nil {
		return nil, memoryWriteOutput{}, err
	}

	// Evaluate statement
	written, err := s.evaluateInSession[uint](
		ctx,
		in.Session,
		fmt.Sprintf(
			`
				(() => {
					const h = %q;
					const b = new Uint8Array(h.length / 2);
					for (let i = 0; i < b.length; i++) {
						b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
					}
					ptr("0x%x").writeByteArray(b);
					return b.length;
				})()
			`,
			strings.ToLower(in.Bytes),
			address,
		),
	)

	if err != nil {
		return nil, memoryWriteOutput{}, fmt.Errorf("write memory: %w", err)
	}

	return nil, memoryWriteOutput{Written: written}, nil
}
