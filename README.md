# MCP Remote Proxy

A Go-based proxy server that enables remote access to Model Context Protocol (MCP) servers over HTTP through Tailscale networks. This proxy bridges the gap between stdio-based MCP clients (like Claude Desktop) and HTTP-based MCP servers running on remote machines.

## Features

- **Tailscale Integration**: Seamlessly connects to MCP servers over your Tailscale network
- **MCP Protocol Support**: Full JSON-RPC 2.0 compatibility with MCP specifications
- **Session Management**: Automatic handling of MCP session IDs for streamable HTTP
- **Authentication Context**: Passes Tailscale user and node information to remote servers
- **Error Handling**: Graceful handling of unsupported methods for Claude Desktop compatibility
- **Flexible Logging**: Configurable logging levels with TTY-aware output formatting

## Prerequisites

- Go 1.19 or later
- Active Tailscale connection
- Access to a remote MCP server via HTTP

## Installation

```bash
# Clone or download the source code
# Build the binary
go build -o mcp-proxy main.go
```

## Usage

### Basic Usage

```bash
./mcp-proxy --server http://your-tailscale-node:8080/mcp
```

### Command Line Options

- `--server` / `MCP_SERVER`: MCP server URL to connect to (required)
- `--verbose` / `-v`: Enable verbose logging
- `--debug` / `-d`: Enable debug logging

### Environment Variables

```bash
export MCP_SERVER=http://your-server:8080/mcp
./mcp-proxy
```

## How It Works

1. **Initialization**: The proxy connects to your local Tailscale client and retrieves user/node information
2. **Message Processing**: Reads JSON-RPC messages from stdin (typically from Claude Desktop)
3. **HTTP Forwarding**: Converts stdio messages to HTTP requests and forwards them to the remote MCP server
4. **Response Handling**: Receives HTTP responses and forwards them back via stdout
5. **Session Management**: Maintains MCP session IDs across requests for optimal performance

## Integration with Claude Desktop

The proxy is designed to work seamlessly with Claude Desktop. Configure it in your MCP settings:

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "/path/to/mcp-proxy",
      "args": ["--server", "http://your-tailscale-node:8080/mcp"]
    }
  }
}
```

## Remote Server Requirements

Your remote MCP server should:

- Accept HTTP POST requests with JSON-RPC 2.0 payloads
- Return appropriate MCP responses
- Optionally handle Tailscale authentication headers:
  - `X-Tailscale-User`: The authenticated user's login name
  - `X-Tailscale-Node`: The client node's DNS name
  - `X-Tailscale-Tags`: Comma-separated list of node tags

## Security Features

- **Tailscale Authentication**: Leverages Tailscale's built-in authentication and encryption
- **User Context**: Passes authenticated user information to remote servers
- **Network Isolation**: Traffic flows through your private Tailscale network
- **No External Dependencies**: Direct communication between trusted nodes

## Logging

The proxy provides multiple logging levels:

- **Default**: Warnings and errors only
- **Verbose** (`-v`): Includes informational messages
- **Debug** (`-d`): Detailed protocol-level debugging

Log output automatically adapts:
- **TTY**: Colorized, human-readable format
- **Non-TTY**: Structured JSON for log aggregation systems

## Error Handling

The proxy includes intelligent error handling:

- **Unsupported Methods**: Converts `-32601` errors to empty results for Claude Desktop compatibility
- **Network Failures**: Proper error propagation with detailed logging
- **Parse Errors**: Graceful handling of malformed JSON-RPC messages
- **HTTP Errors**: Clear error messages for debugging connection issues

## Example Scenarios

### Development Workflow
Run MCP servers on your development machine and access them from Claude Desktop on your laptop, all through your private Tailscale network.

### Team Collaboration
Share MCP tools and resources across team members while maintaining security through Tailscale's access controls.

### Remote Resources
Access MCP servers running on cloud instances or remote machines without exposing them to the public internet.

## Troubleshooting

### Common Issues

**"Tailscale is not running"**
- Ensure Tailscale is installed and authenticated
- Check `tailscale status` command

**"Failed to connect to server"**
- Verify the server URL is accessible via Tailscale
- Check if the remote MCP server is running
- Test connectivity with `curl` or similar tools

**JSON-RPC errors**
- Enable debug logging (`-d`) to inspect message flow
- Verify the remote server implements MCP protocol correctly

### Debug Mode

Enable debug logging to see detailed protocol exchanges:

```bash
./mcp-proxy --server http://your-server:8080/mcp --debug
```

## Dependencies

- `github.com/alecthomas/kong` - CLI parsing
- `go.uber.org/zap` - Structured logging
- `golang.org/x/term` - TTY detection
- `tailscale.com/client/local` - Tailscale client integration

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]