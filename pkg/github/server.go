package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/github/github-mcp-server/pkg/translations"
	"github.com/google/go-github/v69/github"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
)

// GitHubServer encapsulates the GitHub MCP server implementation
type GitHubServer struct {
	client   *github.Client
	version  string
	readOnly bool
	t        translations.TranslationHelperFunc
	server   *server.MCPServer
}

// NewServer creates a new GitHub MCP server with the specified GH client and logger
func NewServer(client *github.Client, version string, readOnly bool, t translations.TranslationHelperFunc) *GitHubServer {
	gh := &GitHubServer{
		client:   client,
		version:  version,
		readOnly: readOnly,
		t:        t,
		server: server.NewMCPServer(
			"github-mcp-server",
			version,
			server.WithResourceCapabilities(true, true),
			server.WithLogging()),
	}

	gh.registerResources()
	gh.registerTools()

	return gh
}

// registerResources registers all GitHub resources
func (gh *GitHubServer) registerResources() {
	gh.server.AddResourceTemplate(gh.GetRepositoryResourceContent())
	gh.server.AddResourceTemplate(gh.GetRepositoryResourceBranchContent())
	gh.server.AddResourceTemplate(gh.GetRepositoryResourceCommitContent())
	gh.server.AddResourceTemplate(gh.GetRepositoryResourceTagContent())
	gh.server.AddResourceTemplate(gh.GetRepositoryResourcePrContent())
}

// registerTools registers all GitHub tools
func (gh *GitHubServer) registerTools() {
	// Register tools based on readOnly mode
	tools := []struct {
		tool    mcp.Tool
		handler server.ToolHandlerFunc
	}{
		{gh.GetMe()},
		{gh.SearchRepositories()},
		{gh.GetFileContents()},
		{gh.ListCommits()},
		{gh.GetPullRequest()},
		{gh.ListPullRequests()},
		{gh.GetPullRequestFiles()},
		{gh.GetPullRequestStatus()},
		{gh.GetPullRequestComments()},
		{gh.GetPullRequestReviews()},
		{gh.SearchCode()},
		{gh.SearchUsers()},
		{gh.GetCodeScanningAlert()},
		{gh.ListCodeScanningAlerts()},
		{gh.GetIssue()},
		{gh.SearchIssues()},
		{gh.ListIssues()},
		{gh.GetIssueComments()},
	}

	for _, t := range tools {
		gh.server.AddTool(t.tool, gh.withToolLogging(t.tool.Name, t.handler))
	}

	if !gh.readOnly {
		writeTools := []struct {
			tool    mcp.Tool
			handler server.ToolHandlerFunc
		}{
			{gh.CreateIssue()},
			{gh.AddIssueComment()},
			{gh.UpdateIssue()},
			{gh.MergePullRequest()},
			{gh.UpdatePullRequestBranch()},
			{gh.CreatePullRequestReview()},
			{gh.CreatePullRequest()},
			{gh.CreateOrUpdateFile()},
			{gh.CreateRepository()},
			{gh.ForkRepository()},
			{gh.CreateBranch()},
			{gh.PushFiles()},
		}

		for _, t := range writeTools {
			gh.server.AddTool(t.tool, gh.withToolLogging(t.tool.Name, t.handler))
		}
	}
}

// GetMe creates a tool to get details of the authenticated user
func (gh *GitHubServer) GetMe() (mcp.Tool, server.ToolHandlerFunc) {
	return mcp.NewTool("get_me",
			mcp.WithDescription(gh.t("TOOL_GET_ME_DESCRIPTION", "Get details of the authenticated GitHub user")),
			mcp.WithString("reason",
				mcp.Description("Optional: reason for accessing this information"),
				mcp.MaxLength(100),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			user, resp, err := gh.client.Users.Get(ctx, "")
			if err != nil {
				if resp != nil {
					return gh.handleGitHubError(resp, "failed to get user details")
				}
				return nil, fmt.Errorf("failed to get user: %w", err)
			}
			defer func() { _ = resp.Body.Close() }()

			userData, err := json.MarshalIndent(user, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("failed to marshal user data: %w", err)
			}

			return mcp.NewToolResultJSON(userData), nil
		}
}

// handleGitHubError handles GitHub API errors consistently
func (gh *GitHubServer) handleGitHubError(resp *github.Response, defaultMsg string, args ...interface{}) (*mcp.CallToolResult, error) {
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return mcp.NewToolResultError(gh.t("ERROR_NOT_FOUND", "Resource not found")), nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var ghErr github.ErrorResponse
	if err := json.Unmarshal(body, &ghErr); err == nil {
		return mcp.NewToolResultError(fmt.Sprintf("%s: %s", ghErr.Message, ghErr.DocumentationURL)), nil
	}

	return mcp.NewToolResultError(fmt.Sprintf(defaultMsg, args...)), nil
}

// isAcceptedError checks if the error is an accepted error
func (gh *GitHubServer) isAcceptedError(err error) bool {
	var acceptedError *github.AcceptedError
	return errors.As(err, &acceptedError)
}

// ParamValidator provides parameter validation utilities
type ParamValidator struct {
	t translations.TranslationHelperFunc
}

// NewParamValidator creates a new parameter validator
func (gh *GitHubServer) NewParamValidator() *ParamValidator {
	return &ParamValidator{t: gh.t}
}

// RequiredString validates a required string parameter
func (pv *ParamValidator) RequiredString(r mcp.CallToolRequest, name string, opts ...ParamOption) (string, error) {
	options := &paramOptions{
		maxLength: 256,
	}
	for _, opt := range opts {
		opt(options)
	}

	value, err := requiredParam[string](r, name)
	if err != nil {
		return "", fmt.Errorf(pv.t("ERROR_PARAM_REQUIRED", "parameter %s is required"), name)
	}

	if len(value) > options.maxLength {
		return "", fmt.Errorf(pv.t("ERROR_PARAM_TOO_LONG", "parameter %s cannot exceed %d characters"), name, options.maxLength)
	}

	return value, nil
}

// paramOptions contains parameter validation options
type paramOptions struct {
	maxLength int
}

// ParamOption configures parameter validation
type ParamOption func(*paramOptions)

// WithMaxLength sets the maximum length for a string parameter
func WithMaxLength(length int) ParamOption {
	return func(o *paramOptions) {
		o.maxLength = length
	}
}

// requiredParam is a generic parameter validator
func requiredParam[T comparable](r mcp.CallToolRequest, p string) (T, error) {
	var zero T

	if _, ok := r.Params.Arguments[p]; !ok {
		return zero, fmt.Errorf("missing required parameter: %s", p)
	}

	if _, ok := r.Params.Arguments[p].(T); !ok {
		return zero, fmt.Errorf("parameter %s is not of type %T", p, zero)
	}

	if r.Params.Arguments[p].(T) == zero {
		return zero, fmt.Errorf("missing required parameter: %s", p)
	}

	return r.Params.Arguments[p].(T), nil
}

// OptionalParam safely retrieves an optional parameter
func OptionalParam[T any](r mcp.CallToolRequest, p string) (T, error) {
	var zero T

	if _, ok := r.Params.Arguments[p]; !ok {
		return zero, nil
	}

	if _, ok := r.Params.Arguments[p].(T); !ok {
		return zero, fmt.Errorf("parameter %s is not of type %T", p, zero)
	}

	return r.Params.Arguments[p].(T), nil
}

// OptionalIntParam retrieves an optional integer parameter
func OptionalIntParam(r mcp.CallToolRequest, p string) (int, error) {
	v, err := OptionalParam[float64](r, p)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

// OptionalIntParamWithDefault retrieves an optional integer parameter with default value
func OptionalIntParamWithDefault(r mcp.CallToolRequest, p string, d int) (int, error) {
	v, err := OptionalIntParam(r, p)
	if err != nil {
		return 0, err
	}
	if v == 0 {
		return d, nil
	}
	return v, nil
}

// OptionalStringArrayParam retrieves an optional string array parameter
func OptionalStringArrayParam(r mcp.CallToolRequest, p string) ([]string, error) {
	if _, ok := r.Params.Arguments[p]; !ok {
		return []string{}, nil
	}

	switch v := r.Params.Arguments[p].(type) {
	case []string:
		return v, nil
	case []any:
		strSlice := make([]string, len(v))
		for i, v := range v {
			s, ok := v.(string)
			if !ok {
				return []string{}, fmt.Errorf("parameter %s contains non-string value", p)
			}
			strSlice[i] = s
		}
		return strSlice, nil
	default:
		return []string{}, fmt.Errorf("parameter %s is not a string array", p)
	}
}

// WithPagination adds pagination parameters to a tool
func WithPagination(defaultPage, defaultPerPage int) mcp.ToolOption {
	return func(tool *mcp.Tool) {
		mcp.WithNumber("page",
			mcp.Description("Page number for pagination"),
			mcp.Min(1),
			mcp.Default(float64(defaultPage)),
		)(tool)

		mcp.WithNumber("perPage",
			mcp.Description("Results per page for pagination"),
			mcp.Min(1),
			mcp.Max(100),
			mcp.Default(float64(defaultPerPage)),
		)(tool)
	}
}

// GetPaginationParams retrieves pagination parameters from a request
func (gh *GitHubServer) GetPaginationParams(r mcp.CallToolRequest) (page, perPage int, err error) {
	pageVal, err := OptionalIntParamWithDefault(r, "page", 1)
	if err != nil {
		return 0, 0, fmt.Errorf(gh.t("ERROR_INVALID_PAGE", "invalid page parameter"))
	}

	perPageVal, err := OptionalIntParamWithDefault(r, "perPage", 30)
	if err != nil {
		return 0, 0, fmt.Errorf(gh.t("ERROR_INVALID_PERPAGE", "invalid perPage parameter"))
	}

	return pageVal, perPageVal, nil
}

// withToolLogging adds logging to tool handlers
func (gh *GitHubServer) withToolLogging(toolName string, handler server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		start := time.Now()
		
		logger := zap.L().With(
			zap.String("tool", toolName),
			zap.Any("params", req.Params.Arguments),
		)
		logger.Info("Tool execution started")

		result, err := handler(ctx, req)

		logger.Info("Tool execution completed",
			zap.Duration("duration", time.Since(start)),
			zap.Error(err))

		return result, err
	}
}

// Note: The actual tool implementations (like GetRepositoryResourceContent, CreateIssue, etc.)
// would follow the same patterns shown in GetMe, but are omitted for brevity.
// Each would use the improved parameter handling, error handling, and logging.
