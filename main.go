package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/term"
	"tailscale.com/client/local"
)

// CLI represents the command line interface
type CLI struct {
	Server  string `kong:"help='MCP server to connect to',env='MCP_SERVER'"`
	Verbose bool   `kong:"help='Enable verbose logging',short='v',name='verbose'"`
	Debug   bool   `kong:"help='Enable debug logging',short='d',name='debug'"`
}

var logger *zap.Logger

// MCPMessage represents a JSON-RPC 2.0 message with strict validation
type MCPMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

// MCPError represents a JSON-RPC error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Proxy handles the MCP proxying logic
type Proxy struct {
	cli        *CLI
	tsClient   *local.Client
	httpClient *http.Client
	userLogin  string
	sessionID  string
}

// createValidResponse creates a properly formatted JSON-RPC 2.0 response
func createValidResponse(requestID interface{}, result interface{}, err *MCPError) *MCPMessage {
	// Ensure ID is never null - convert to appropriate type
	var responseID interface{}
	if requestID == nil {
		responseID = 0 // Use 0 instead of null
	} else {
		responseID = requestID
	}

	msg := &MCPMessage{
		JSONRPC: "2.0",
		ID:      responseID,
	}

	if err != nil {
		msg.Error = err
		msg.Result = nil
	} else {
		msg.Result = result
		msg.Error = nil
	}

	// Clear method and params for responses
	msg.Method = ""
	msg.Params = nil

	return msg
}

// initLogger initializes the Zap logger based on environment and debug settings
func initLogger(debug bool, verbose bool) {
	var config zap.Config

	// Check if we're running in a TTY
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	if isTTY {
		// Pretty console output for TTY
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
	} else {
		// Structured JSON output for non-TTY (production/logging systems)
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Set log level based on debug/verbose flags
	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else if verbose {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	}

	var err error
	logger, err = config.Build()
	if err != nil {
		log.Fatal("Failed to initialize logger:", err)
	}

	// Replace standard logger with zap
	zap.ReplaceGlobals(logger)
}

// NewProxy - create a new MCP proxy instance
func NewProxy(cli *CLI) (*Proxy, error) {
	// We'll use the local Tailscale client to interact with the Tailscale network
	tsClient := &local.Client{}

	// Create HTTP client that uses Tailscale's network
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &Proxy{
		cli:        cli,
		tsClient:   tsClient,
		httpClient: httpClient,
	}, nil
}

// Initialize sets up the proxy with authentication
func (p *Proxy) Initialize(ctx context.Context) error {
	// Get current Tailscale status
	status, err := p.tsClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	if status.BackendState != "Running" {
		return fmt.Errorf("Tailscale is not running (state: %s)", status.BackendState)
	}

	// Get user information
	user := status.User[status.Self.UserID]
	p.userLogin = user.LoginName

	logger.Info("Proxy initialized",
		zap.String("user", p.userLogin),
		zap.String("node", status.Self.DNSName),
		zap.String("backend_state", status.BackendState),
	)

	return nil
}

// Run starts the proxy server
func (p *Proxy) Run(ctx context.Context) error {
	if p.cli.Server == "" {
		return fmt.Errorf("MCP server must be specified")
	}

	// Parse server URL
	serverURL, err := url.Parse(p.cli.Server)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	logger.Info("Starting MCP proxy",
		zap.String("server", p.cli.Server),
		zap.String("user", p.userLogin),
	)

	// Start the stdio proxy loop
	return p.proxyLoop(ctx, serverURL)
}

// sendResponse sends a JSON-RPC response via stdout
func (p *Proxy) sendResponse(response *MCPMessage) error {
	responseBytes, err := json.Marshal(response)
	if err != nil {
		logger.Error("Failed to marshal response", zap.Error(err))
		return err
	}

	logger.Debug("Sending response", zap.String("response", string(responseBytes)))

	// Write directly to stdout with newline
	if _, err := os.Stdout.Write(responseBytes); err != nil {
		return err
	}
	if _, err := os.Stdout.Write([]byte("\n")); err != nil {
		return err
	}
	os.Stdout.Sync()
	return nil
}

// proxyLoop handles the main proxy loop between stdio and HTTP
func (p *Proxy) proxyLoop(ctx context.Context, serverURL *url.URL) error {
	scanner := bufio.NewScanner(os.Stdin)

	logger.Debug("Starting proxy loop")

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse the MCP message
		var msg MCPMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			logger.Error("Failed to parse MCP message",
				zap.Error(err),
				zap.String("raw_message", line),
			)
			errorResponse := createValidResponse(nil, nil, &MCPError{
				Code:    -32700,
				Message: "Parse error",
				Data:    err.Error(),
			})
			p.sendResponse(errorResponse)
			continue
		}

		logger.Debug("Received MCP message",
			zap.String("method", msg.Method),
			zap.Any("id", msg.ID),
		)

		// Forward the message to the remote MCP server
		response, err := p.forwardMessage(ctx, serverURL, &msg)
		if err != nil {
			logger.Error("Failed to forward message",
				zap.String("method", msg.Method),
				zap.Any("id", msg.ID),
				zap.Error(err),
			)
			errorResponse := createValidResponse(msg.ID, nil, &MCPError{
				Code:    -32603,
				Message: "Internal error",
				Data:    err.Error(),
			})
			p.sendResponse(errorResponse)
			continue
		}

		// Send the response
		if err := p.sendResponse(response); err != nil {
			logger.Error("Failed to send response", zap.Error(err))
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Scanner error", zap.Error(err))
		return err
	}

	logger.Debug("Proxy loop ended")
	return nil
}

// forwardMessage forwards an MCP message to the remote server
func (p *Proxy) forwardMessage(ctx context.Context, serverURL *url.URL, msg *MCPMessage) (*MCPMessage, error) {
	// Serialize the message
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	logger.Debug("Forwarding message to server",
		zap.String("server", serverURL.String()),
		zap.String("method", msg.Method),
		zap.Any("id", msg.ID),
	)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", serverURL.String(), bytes.NewReader(msgBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MCP-Remote-Proxy/1.0")

	// Add MCP session ID if we have one
	if p.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", p.sessionID)
	}

	// Add Tailscale authentication headers
	req.Header.Set("X-Tailscale-User", p.userLogin)

	// Add additional context headers
	status, err := p.tsClient.Status(ctx)
	if err == nil {
		req.Header.Set("X-Tailscale-Node", status.Self.DNSName)

		// Convert tags to string slice for header
		tags := status.Self.Tags
		if tags != nil && tags.Len() > 0 {
			var tagSlice []string
			for i := 0; i < tags.Len(); i++ {
				tagSlice = append(tagSlice, tags.At(i))
			}
			req.Header.Set("X-Tailscale-Tags", strings.Join(tagSlice, ","))
		}
	}

	// Send the request
	start := time.Now()
	resp, err := p.httpClient.Do(req)
	duration := time.Since(start)

	if err != nil {
		logger.Error("HTTP request failed",
			zap.String("server", serverURL.String()),
			zap.String("method", msg.Method),
			zap.Duration("duration", duration),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	logger.Debug("HTTP request completed",
		zap.String("server", serverURL.String()),
		zap.String("method", msg.Method),
		zap.Int("status_code", resp.StatusCode),
		zap.Duration("duration", duration),
	)

	// Extract MCP session ID from response headers
	if sessionID := resp.Header.Get("Mcp-Session-Id"); sessionID != "" {
		if p.sessionID != sessionID {
			logger.Info("Received new MCP session ID", zap.String("session_id", sessionID))
			p.sessionID = sessionID
		}
	}

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read response body", zap.Error(err))
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	logger.Debug("Received response",
		zap.Int("status_code", resp.StatusCode),
		zap.String("response_body", string(respBody)),
	)

	if resp.StatusCode != http.StatusOK {
		logger.Error("Server returned error status",
			zap.Int("status_code", resp.StatusCode),
			zap.String("response_body", string(respBody)),
		)
		
		return createValidResponse(msg.ID, nil, &MCPError{
			Code:    -32603,
			Message: fmt.Sprintf("Server error (HTTP %d)", resp.StatusCode),
			Data:    string(respBody),
		}), nil
	}

	// Parse the response
	var response MCPMessage
	if err := json.Unmarshal(respBody, &response); err != nil {
		logger.Error("Failed to parse response JSON",
			zap.Error(err),
			zap.String("response_body", string(respBody)),
		)
		
		return createValidResponse(msg.ID, nil, &MCPError{
			Code:    -32700,
			Message: "Parse error",
			Data:    fmt.Sprintf("Failed to parse server response: %v", err),
		}), nil
	}

	// Create a clean response with proper validation
	if response.Error != nil {
		// Handle unsupported method errors gracefully
		if response.Error.Code == -32601 {
			logger.Info("Converting unsupported method error to empty result",
				zap.String("method", msg.Method),
			)

			// Convert to successful empty response based on method
			var result interface{}
			switch msg.Method {
			case "prompts/list":
				result = map[string]interface{}{"prompts": []interface{}{}}
			case "prompts/get":
				result = map[string]interface{}{"messages": []interface{}{}}
			case "resources/list":
				result = map[string]interface{}{"resources": []interface{}{}}
			case "tools/list":
				result = map[string]interface{}{"tools": []interface{}{}}
			default:
				result = map[string]interface{}{}
			}

			return createValidResponse(msg.ID, result, nil), nil
		}

		// Return the error response
		return createValidResponse(msg.ID, nil, response.Error), nil
	}

	// Return the success response
	return createValidResponse(msg.ID, response.Result, nil), nil
}

func main() {
	var cli CLI
	kong.Parse(&cli)

	// Initialize logger early
	initLogger(cli.Debug, cli.Verbose)
	defer logger.Sync()

	logger.Info("Starting MCP Remote Proxy",
		zap.String("server", cli.Server),
		zap.Bool("verbose", cli.Verbose),
		zap.Bool("debug", cli.Debug),
	)

	proxy, err := NewProxy(&cli)
	if err != nil {
		logger.Fatal("Failed to create proxy", zap.Error(err))
	}

	if err := proxy.Initialize(context.Background()); err != nil {
		logger.Fatal("Failed to initialize proxy", zap.Error(err))
	}

	if err := proxy.Run(context.Background()); err != nil {
		logger.Fatal("Proxy failed", zap.Error(err))
	}
}