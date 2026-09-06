package frida

import (
	_ "embed"

	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// evaluatorScript is the JavaScript source of the persistent evaluator.
//
//go:embed assets/evaluator.js
var evaluatorScript string

// errEvaluatorClosed indicates that the evaluator was closed.
var errEvaluatorClosed = errors.New("evaluator already closed")

// Request and response types for the evaluator script.
type evaluationRequest struct {
	Type    string                   `json:"type"`
	Payload evaluationRequestPayload `json:"payload"`
}

type evaluationRequestPayload struct {
	ID     uint64 `json:"id"`
	Source string `json:"source"`
}

type evaluationResponse struct {
	Type    string                    `json:"type"`
	Payload evaluationResponsePayload `json:"payload"`
}

type evaluationResponsePayload struct {
	ID     uint64                          `json:"id"`
	Result json.RawMessage                 `json:"result"`
	Error  *evaluationResponsePayloadError `json:"error"`
}

type evaluationResponsePayloadError struct {
	Name    string `json:"name"`
	Message string `json:"message"`
	Stack   string `json:"stack"`
}

// Evaluator is a persistent JavaScript evaluator running in a Frida session.
type Evaluator struct {
	mu        sync.Mutex // Guards evaluator state.
	closed    bool       // Whether resources were released.
	script    *Script    // Backing script.
	requestID uint64     // Eval request ID.
}

// NewEvaluator creates a persistent JavaScript evaluator in the given session.
func NewEvaluator(ctx context.Context, session *Session) (*Evaluator, error) {
	// Create evaluator script
	script, err := session.CreateAndLoadScript(ctx, evaluatorScript)
	if err != nil {
		return nil, fmt.Errorf("create evaluator script: %w", err)
	}

	// Return evaluator instance
	return &Evaluator{script: script}, nil
}

// Close unloads the evaluator's script and releases resources.
func (e *Evaluator) Close(ctx context.Context) error {
	// Synchronize access
	e.mu.Lock()
	defer e.mu.Unlock()

	// Early exit if already closed
	if e.closed {
		return nil
	}

	e.closed = true

	// Clean up
	err := e.script.Close(ctx)
	e.script = nil

	return err
}

// Evaluate runs statement in the evaluator and returns its JSON result.
func (e *Evaluator) Evaluate(ctx context.Context, statement string) (json.RawMessage, error) {
	// Synchronize access
	e.mu.Lock()
	defer e.mu.Unlock()

	// Early exit if evaluator is already closed
	if e.closed {
		return nil, errEvaluatorClosed
	}

	// Encode request
	e.requestID++

	encoded, err := json.Marshal(evaluationRequest{
		Type: "evaluate",
		Payload: evaluationRequestPayload{
			ID:     e.requestID,
			Source: statement,
		},
	})

	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	// Post request to script
	if err := e.script.Post(string(encoded), nil); err != nil {
		return nil, fmt.Errorf("post request: %w", err)
	}

	// Wait for matching response
	for {
		select {
		case message := <-e.script.messages:
			// Decode response
			var response evaluationResponse

			if err := json.Unmarshal([]byte(message.JSON), &response); err != nil {
				return nil, fmt.Errorf("decode response: %w", err)
			}

			// Skip messages that are not evaluation responses
			if response.Type != "send" {
				continue
			}

			// Skip responses for other requests
			if response.Payload.ID != e.requestID {
				continue
			}

			// Report evaluation errors
			if response.Payload.Error != nil {
				return nil, fmt.Errorf("javascript error [name=%s]: %s", response.Payload.Error.Name, response.Payload.Error.Message)
			}

			return response.Payload.Result, nil

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}
