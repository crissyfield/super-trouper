package codeshare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrNotFound is returned when a requested project does not exist.
var ErrNotFound = errors.New("project not found")

// API URL formats of the CodeShare endpoints.
const (
	searchURLFormat  = "https://codeshare.frida.re/api/projects/search?%s"
	popularURLFormat = "https://codeshare.frida.re/api/projects/popular?%s"
	projectURLFormat = "https://codeshare.frida.re/api/project/%s/%s/"
)

// Default limits for the Search and Popular functions.
const defaultLimit = 10

// CodeShare is a client for the Frida CodeShare API.
type CodeShare struct {
	client *http.Client // HTTP client used for API requests.
}

// Option configures a CodeShare client.
type Option func(*CodeShare)

// WithHTTPClient sets the HTTP client used for API requests. If not given, the default HTTP client is used.
func WithHTTPClient(client *http.Client) Option {
	return func(c *CodeShare) { c.client = client }
}

// New creates a new CodeShare client.
func New(opts ...Option) *CodeShare {
	// Create client instance
	share := &CodeShare{}

	// Apply options
	for _, opt := range opts {
		opt(share)
	}

	if share.client == nil {
		share.client = http.DefaultClient
	}

	// Return instance
	return share
}

// searchOptions contains the options for the Search function.
type searchOptions struct {
	limit int // Maximum number of projects to return.
}

// SearchOption configures the Search function.
type SearchOption func(*searchOptions)

// WithSearchLimit sets the maximum number of projects Search returns. If not given a default of 10 is used.
func WithSearchLimit(limit int) SearchOption {
	return func(o *searchOptions) { o.limit = limit }
}

// Search searches Frida CodeShare where query matches against project names, descriptions, and source code.
func (c *CodeShare) Search(ctx context.Context, query string, opts ...SearchOption) ([]Project, error) {
	// Apply options
	var config searchOptions

	for _, opt := range opts {
		opt(&config)
	}

	if config.limit <= 0 {
		config.limit = defaultLimit
	}

	// Fetch projects
	var projects []Project

	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", fmt.Sprintf("%d", config.limit))

	err := c.fetch(
		ctx,
		fmt.Sprintf(searchURLFormat, params.Encode()),
		&projects,
	)

	if err != nil {
		return nil, fmt.Errorf("fetch projects: %w", err)
	}

	return projects, nil
}

// popularOptions contains the options for the Popular function.
type popularOptions struct {
	limit int // Maximum number of projects to return.
}

// PopularOption configures the Popular function.
type PopularOption func(*popularOptions)

// WithPopularLimit sets the maximum number of projects Popular returns. If not given a default of 10 is used.
func WithPopularLimit(limit int) PopularOption {
	return func(o *popularOptions) { o.limit = limit }
}

// Popular returns the most popular projects on Frida CodeShare.
func (c *CodeShare) Popular(ctx context.Context, opts ...PopularOption) ([]Project, error) {
	// Apply options
	var config popularOptions

	for _, opt := range opts {
		opt(&config)
	}

	if config.limit <= 0 {
		config.limit = defaultLimit
	}

	// Fetch projects
	var projects []Project

	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", config.limit))

	err := c.fetch(
		ctx,
		fmt.Sprintf(popularURLFormat, params.Encode()),
		&projects,
	)

	if err != nil {
		return nil, fmt.Errorf("fetch projects: %w", err)
	}

	return projects, nil
}

// Project returns the project with the given owner and slug from the Frida CodeShare. The returned
// project includes the JavaScript source.
func (c *CodeShare) Project(ctx context.Context, owner string, slug string) (Project, error) {
	// Fetch project
	var project Project

	err := c.fetch(
		ctx,
		fmt.Sprintf(projectURLFormat, url.PathEscape(owner), url.PathEscape(slug)),
		&project,
	)

	if err != nil {
		return Project{}, fmt.Errorf("fetch project: %w", err)
	}

	return project, nil
}

// fetch performs a GET request against the given URL and decodes the JSON response into the given target.
func (c *CodeShare) fetch(ctx context.Context, url string, target any) error {
	// Create request
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Perform request
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("perform request: %w", err)
	}

	defer response.Body.Close()

	// Check status
	if response.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response [status=%d]", response.StatusCode)
	}

	// Decode response
	err = json.NewDecoder(response.Body).Decode(target)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}
