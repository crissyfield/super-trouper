package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"uuid"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/crissyfield/super-trouper/internal/frida"
)

// deviceState contains the state of a Frida device created by the 'device_connect' tool.
type deviceState struct {
	device  *frida.Device // Underlying Frida device.
	key     string        // Connect key, used to make 'device_connect' idempotent.
	address string        // Address of remote devices, empty otherwise.
}

// addDevicesTools registers the device tools.
func (s *MCPServer) addDevicesTools() {
	// List detected devices
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "device_list",
		Description: "Lists the Frida devices detected by the host.",
	}, s.deviceList)

	// Connect to a device
	mcp.AddTool(s.server, &mcp.Tool{
		Name: "device_connect",
		Description: "Connects to a Frida device, either by ID as reported by device_list, by the address of " +
			"a remote Frida server, or by type. Returns a device handle used by the other device tools. " +
			"Connecting to the same device again returns the existing handle.",
	}, s.deviceConnect)

	// Disconnect from a device
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "device_disconnect",
		Description: "Disconnects from a Frida device. Fails while the device still has attached sessions.",
	}, s.deviceDisconnect)

	// Query device parameters
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "device_params",
		Description: "Returns the parameters of a Frida device.",
	}, s.deviceParams)

	// Spawn a suspended process
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "device_spawn",
		Description: "Spawns a process on a Frida device in a suspended state. Use device_resume to start it.",
	}, s.deviceSpawn)

	// Resume a process
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "device_resume",
		Description: "Resumes a suspended process on a Frida device.",
	}, s.deviceResume)

	// Kill a process
	mcp.AddTool(s.server, &mcp.Tool{
		Name:        "device_kill",
		Description: "Kills a process on a Frida device.",
	}, s.deviceKill)
}

// lookupDeviceState returns the state of the lookupDeviceState with the given handle. The caller must hold the
// mutex.
func (s *MCPServer) lookupDeviceState(handle string) (*deviceState, error) {
	state, ok := s.devices[handle]
	if !ok {
		return nil, fmt.Errorf("unknown device handle [handle=%s]", handle)
	}

	return state, nil
}

// closeFridaDevices closes the given Frida devices with a timeout context and logs any error.
func closeFridaDevices(devices ...*frida.Device) {
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Close devices
	for _, device := range devices {
		if err := device.Close(timeoutCtx); err != nil {
			slog.Error("Close device", slog.Any("error", err))
		}
	}
}

// deviceInfo describes a Frida device.
type deviceInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// deviceListInput contains the input arguments of the 'device_list' tool.
type deviceListInput struct{}

// deviceListOutput contains the output of the 'device_list' tool.
type deviceListOutput struct {
	Devices []deviceInfo `json:"devices" jsonschema:"the devices detected by the host"`
}

// deviceList implements the 'device_list' tool.
func (s *MCPServer) deviceList(ctx context.Context, _ *mcp.CallToolRequest, _ deviceListInput) (*mcp.CallToolResult, deviceListOutput, error) {
	// Enumerate devices
	devices, err := s.manager.EnumerateDevices(ctx)
	if err != nil {
		return nil, deviceListOutput{}, fmt.Errorf("enumerate devices: %w", err)
	}

	// Collect device information
	infos := make([]deviceInfo, 0, len(devices))

	for _, device := range devices {
		infos = append(infos, deviceInfo{
			ID:   device.ID(),
			Name: device.Name(),
			Type: string(device.Type()),
		})
	}

	// Release the device wrappers once the device information was copied
	closeFridaDevices(devices...)

	return nil, deviceListOutput{Devices: infos}, nil
}

// deviceConnectInput contains the input arguments of the 'device_connect' tool.
type deviceConnectInput struct {
	ID      string `json:"id,omitempty" jsonschema:"ID of the device to connect to, as reported by device_list"`
	Address string `json:"address,omitempty" jsonschema:"address of a remote Frida server in host:port form"`
	Type    string `json:"type,omitempty" jsonschema:"type of a local device to connect to, either local or usb"`
}

// deviceConnectOutput contains the output of the 'device_connect' tool.
type deviceConnectOutput struct {
	Device string `json:"device" jsonschema:"handle of the connected device, used by the other device tools"`
	ID     string `json:"id"`
	Name   string `json:"name"`
	Type   string `json:"type"`
}

// deviceConnect implements the 'device_connect' tool.
func (s *MCPServer) deviceConnect(ctx context.Context, _ *mcp.CallToolRequest, in deviceConnectInput) (*mcp.CallToolResult, deviceConnectOutput, error) {
	// Validate input and determine connect key
	var key string

	switch {
	case (in.ID != "") && (in.Address == "") && (in.Type == ""):
		key = "id:" + in.ID

	case (in.ID == "") && (in.Address != "") && (in.Type == ""):
		key = "address:" + in.Address

	case (in.ID == "") && (in.Address == "") && (in.Type != ""):
		if (in.Type != string(frida.DeviceTypeLocal)) && (in.Type != string(frida.DeviceTypeUSB)) {
			return nil, deviceConnectOutput{}, fmt.Errorf("invalid device type [type=%s]", in.Type)
		}

		key = "type:" + in.Type

	default:
		return nil, deviceConnectOutput{}, errors.New("either device ID, address, or type must be given")
	}

	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up or connect to device
	if handle, ok := s.keys[key]; ok {
		state := s.devices[handle]

		return nil, deviceConnectOutput{
			Device: handle,
			ID:     state.device.ID(),
			Name:   state.device.Name(),
			Type:   string(state.device.Type()),
		}, nil
	}

	// Connect to device
	var device *frida.Device
	var err error

	switch {
	case in.ID != "":
		device, err = s.manager.GetDeviceByID(ctx, in.ID)

	case in.Address != "":
		device, err = s.manager.AddRemoteDevice(ctx, in.Address)

	default:
		device, err = s.manager.GetDeviceByType(ctx, frida.DeviceType(in.Type))
	}

	if err != nil {
		return nil, deviceConnectOutput{}, fmt.Errorf("connect to device: %w", err)
	}

	// Register device
	handle := uuid.New().String()
	state := &deviceState{
		device:  device,
		key:     key,
		address: in.Address,
	}

	s.devices[handle] = state
	s.keys[key] = handle

	return nil, deviceConnectOutput{
		Device: handle,
		ID:     state.device.ID(),
		Name:   state.device.Name(),
		Type:   string(state.device.Type()),
	}, nil
}

// deviceDisconnectInput contains the input arguments of the 'device_disconnect' tool.
type deviceDisconnectInput struct {
	Device string `json:"device" jsonschema:"handle of the device to disconnect from"`
}

// deviceDisconnectOutput contains the output of the 'device_disconnect' tool.
type deviceDisconnectOutput struct{}

// deviceDisconnect implements the 'device_disconnect' tool.
func (s *MCPServer) deviceDisconnect(ctx context.Context, _ *mcp.CallToolRequest, in deviceDisconnectInput) (*mcp.CallToolResult, deviceDisconnectOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device and make sure it has no attached sessions
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, deviceDisconnectOutput{}, err
	}

	for handle, session := range s.sessions {
		if session.deviceHandle == in.Device {
			return nil, deviceDisconnectOutput{}, fmt.Errorf("device has active sessions [device=%s, session=%s]", in.Device, handle)
		}
	}

	// Remove device from state
	delete(s.devices, in.Device)
	delete(s.keys, state.key)

	// Remove the remote device
	if state.address != "" {
		err := s.manager.RemoveRemoteDevice(ctx, state.address)
		if err != nil {
			return nil, deviceDisconnectOutput{}, fmt.Errorf("remove remote device: %w", err)
		}
	}

	closeFridaDevices(state.device)

	return nil, deviceDisconnectOutput{}, nil
}

// deviceParamsInput contains the input arguments of the 'device_params' tool.
type deviceParamsInput struct {
	Device string `json:"device" jsonschema:"handle of the device to query"`
}

// deviceParamsOutput contains the output of the 'device_params' tool.
type deviceParamsOutput struct {
	Params map[string]any `json:"params" jsonschema:"the parameters of the device"`
}

// deviceParams implements the 'device_params' tool.
func (s *MCPServer) deviceParams(ctx context.Context, _ *mcp.CallToolRequest, in deviceParamsInput) (*mcp.CallToolResult, deviceParamsOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, deviceParamsOutput{}, err
	}

	// Query device parameters
	params, err := state.device.Params(ctx)
	if err != nil {
		return nil, deviceParamsOutput{}, fmt.Errorf("query device parameters: %w", err)
	}

	return nil, deviceParamsOutput{Params: params}, nil
}

// deviceSpawnInput contains the input arguments of the 'device_spawn' tool.
type deviceSpawnInput struct {
	Device string            `json:"device" jsonschema:"handle of the device to spawn the process on"`
	Name   string            `json:"name" jsonschema:"name or path of the program to spawn"`
	Argv   []string          `json:"argv,omitempty" jsonschema:"arguments to pass to the program"`
	Env    map[string]string `json:"env,omitempty" jsonschema:"environment variables to set for the process"`
	Cwd    string            `json:"cwd,omitempty" jsonschema:"working directory of the process"`
}

// deviceSpawnOutput contains the output of the 'device_spawn' tool.
type deviceSpawnOutput struct {
	PID uint `json:"pid" jsonschema:"PID of the suspended process"`
}

// deviceSpawn implements the 'device_spawn' tool.
func (s *MCPServer) deviceSpawn(ctx context.Context, _ *mcp.CallToolRequest, in deviceSpawnInput) (*mcp.CallToolResult, deviceSpawnOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, deviceSpawnOutput{}, err
	}

	// Assemble spawn options
	var options []frida.SpawnOption

	if len(in.Argv) != 0 {
		options = append(options, frida.WithSpawnArgv(in.Argv))
	}

	if len(in.Env) != 0 {
		options = append(options, frida.WithSpawnEnv(in.Env))
	}

	if in.Cwd != "" {
		options = append(options, frida.WithSpawnCwd(in.Cwd))
	}

	// Spawn process
	pid, err := state.device.Spawn(ctx, in.Name, options...)
	if err != nil {
		return nil, deviceSpawnOutput{}, fmt.Errorf("spawn process: %w", err)
	}

	return nil, deviceSpawnOutput{PID: pid}, nil
}

// deviceResumeInput contains the input arguments of the 'device_resume' tool.
type deviceResumeInput struct {
	Device string `json:"device" jsonschema:"handle of the device owning the process"`
	PID    uint   `json:"pid" jsonschema:"PID of the process to resume"`
}

// deviceResumeOutput contains the output of the 'device_resume' tool.
type deviceResumeOutput struct{}

// deviceResume implements the 'device_resume' tool.
func (s *MCPServer) deviceResume(ctx context.Context, _ *mcp.CallToolRequest, in deviceResumeInput) (*mcp.CallToolResult, deviceResumeOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, deviceResumeOutput{}, err
	}

	// Resume process
	if err := state.device.Resume(ctx, in.PID); err != nil {
		return nil, deviceResumeOutput{}, fmt.Errorf("resume process: %w", err)
	}

	return nil, deviceResumeOutput{}, nil
}

// deviceKillInput contains the input arguments of the 'device_kill' tool.
type deviceKillInput struct {
	Device string `json:"device" jsonschema:"handle of the device owning the process"`
	PID    uint   `json:"pid" jsonschema:"PID of the process to kill"`
}

// deviceKillOutput contains the output of the 'device_kill' tool.
type deviceKillOutput struct{}

// deviceKill implements the 'device_kill' tool.
func (s *MCPServer) deviceKill(ctx context.Context, _ *mcp.CallToolRequest, in deviceKillInput) (*mcp.CallToolResult, deviceKillOutput, error) {
	// Synchronize access
	s.mu.Lock()
	defer s.mu.Unlock()

	// Look up device
	state, err := s.lookupDeviceState(in.Device)
	if err != nil {
		return nil, deviceKillOutput{}, err
	}

	// Kill process
	if err := state.device.Kill(ctx, in.PID); err != nil {
		return nil, deviceKillOutput{}, fmt.Errorf("kill process: %w", err)
	}

	return nil, deviceKillOutput{}, nil
}
