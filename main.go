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
	"tailscale.com/client/local"
)

// CLI represents the command line interface
type CLI struct {
	Server  string `kong:"help='MCP server to connect to',env='MCP_SERVER'"`
	Verbose bool   `kong:"help='Enable verbose logging',short='v',name='verbose'"`
}

// MCPMessage represents a JSON-RPC 2.0 message
type MCPMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
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
	sessionID  string // MCP session ID for streamable HTTP
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

	if p.cli.Verbose {
		log.Printf("Authenticated as: %s", p.userLogin)
		log.Printf("Tailscale node: %s", status.Self.DNSName)
	}

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

	if p.cli.Verbose {
		log.Printf("Starting MCP proxy for server: %s", p.cli.Server)
	}

	// Start the stdio proxy loop
	return p.proxyLoop(ctx, serverURL)
}

// proxyLoop handles the main proxy loop between stdio and HTTP
func (p *Proxy) proxyLoop(ctx context.Context, serverURL *url.URL) error {
	scanner := bufio.NewScanner(os.Stdin)
	
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse the MCP message
		var msg MCPMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			p.sendError(nil, -32700, "Parse error", err.Error())
			continue
		}

		if p.cli.Verbose {
			log.Printf("Forwarding message: %s (id: %v)", msg.Method, msg.ID)
		}

		// Forward the message to the remote MCP server
		response, err := p.forwardMessage(ctx, serverURL, &msg)
		if err != nil {
			if p.cli.Verbose {
				log.Printf("Error forwarding message: %v", err)
			}
			p.sendError(msg.ID, -32603, "Internal error", err.Error())
			continue
		}

		// Send the response back via stdio
		responseBytes, err := json.Marshal(response)
		if err != nil {
			p.sendError(msg.ID, -32603, "Internal error", err.Error())
			continue
		}

		if p.cli.Verbose {
			log.Printf("Sending response: %s", string(responseBytes))
		}

		fmt.Println(string(responseBytes))
	}

	return scanner.Err()
}

// forwardMessage forwards an MCP message to the remote server using MCP streamable HTTP protocol
func (p *Proxy) forwardMessage(ctx context.Context, serverURL *url.URL, msg *MCPMessage) (*MCPMessage, error) {
	// Serialize the message
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	if p.cli.Verbose {
		log.Printf("Sending MCP message: %s", string(msgBytes))
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", serverURL.String(), bytes.NewReader(msgBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MCP-Remote-Proxy/1.0")

	// Add MCP session ID if we have one (for subsequent requests)
	if p.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", p.sessionID)
		if p.cli.Verbose {
			log.Printf("Using MCP session ID: %s", p.sessionID)
		}
	}

	// Add Tailscale authentication headers for server identification
	// if the remote server can handle Tailscale auth
	// this can be used to identify the user and node
	// and set permissions via Tailscale grants
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
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Extract MCP session ID from response headers (for first request or session renewal)
	if sessionID := resp.Header.Get("Mcp-Session-Id"); sessionID != "" {
		if p.sessionID != sessionID {
			if p.cli.Verbose {
				log.Printf("Got new MCP session ID: %s", sessionID)
			}
			p.sessionID = sessionID
		}
	}

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if p.cli.Verbose {
		log.Printf("Received MCP response (status %d): %s", resp.StatusCode, string(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse the response
	var response MCPMessage
	if err := json.Unmarshal(respBody, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Handle unsupported method errors gracefully for Claude Desktop compatibility
	if response.Error != nil && response.Error.Code == -32601 {
		if p.cli.Verbose {
			log.Printf("Converting unsupported method error to empty result for method: %s", msg.Method)
		}
		
		// Convert to successful empty response based on method
		switch msg.Method {
		case "prompts/list":
			response = MCPMessage{
				JSONRPC: "2.0",
				ID:      response.ID,
				Result:  map[string]interface{}{"prompts": []interface{}{}},
				Error:   nil,
			}
		case "prompts/get":
			response = MCPMessage{
				JSONRPC: "2.0",
				ID:      response.ID,
				Result:  map[string]interface{}{"messages": []interface{}{}},
				Error:   nil,
			}
		default:
			// For other unsupported methods, return empty result
			response = MCPMessage{
				JSONRPC: "2.0",
				ID:      response.ID,
				Result:  map[string]interface{}{},
				Error:   nil,
			}
		}
	}

	return &response, nil
}

// sendError sends an error response via stdio
func (p *Proxy) sendError(id interface{}, code int, message, data string) {
	errorMsg := MCPMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &MCPError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}

	errorBytes, err := json.Marshal(errorMsg)
	if err != nil {
		log.Printf("Failed to marshal error: %v", err)
		return
	}

	fmt.Println(string(errorBytes))
}

func main() {
	var cli CLI
	kong.Parse(&cli)

	proxy, err := NewProxy(&cli)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	if err := proxy.Initialize(context.Background()); err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}

	if err := proxy.Run(context.Background()); err != nil {
		log.Fatalf("Proxy failed: %v", err)
	}
}