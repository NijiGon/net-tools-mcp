# Net Tools MCP Server

MCP server providing network diagnostic tools.

## Installation

```bash
npm install -g net-tools-mcp
```

Or use with npx (no installation required):

```bash
npx net-tools-mcp
```

## Usage

Configure in your MCP client:

```json
{
  "mcpServers": {
    "net-tools": {
      "command": "npx",
      "args": ["-y", "net-tools-mcp"]
    }
  }
}
```

Or if installed globally:

```json
{
  "mcpServers": {
    "net-tools": {
      "command": "net-tools-mcp"
    }
  }
}
```

## Tools

- **ping**: Test host connectivity
- **nslookup**: DNS lookup
- **netstat**: Network connections/statistics
- **telnet**: Test TCP port connectivity
- **ssh**: Execute remote SSH commands
