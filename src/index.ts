#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

const sanitizeInput = (input: string): string => {
  return input.replace(/[;&|`$(){}\[\]<>\n\r]/g, "");
};

const validateHost = (host: string): boolean => {
  const hostRegex = /^[a-zA-Z0-9.-]+$/;
  return hostRegex.test(host);
};

const validateDomain = (domain: string): boolean => {
  const domainRegex = /^[a-zA-Z0-9.-]+$/;
  return domainRegex.test(domain);
};

const validateUrl = (url: string): boolean => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

const validatePath = (path: string): boolean => {
  const pathRegex = /^[a-zA-Z0-9._\/-]+$/;
  return pathRegex.test(path);
};

const server = new Server(
  { name: "net-tools-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "ping",
      description: "Ping a host to check connectivity",
      inputSchema: {
        type: "object",
        properties: {
          host: { type: "string", description: "Hostname or IP address" },
          count: { type: "number", description: "Number of packets (default: 4)" },
          timeout: { type: "number", description: "Timeout in seconds" },
          packetSize: { type: "number", description: "Packet size in bytes" },
          ttl: { type: "number", description: "Time to live" }
        },
        required: ["host"]
      }
    },
    {
      name: "nslookup",
      description: "DNS lookup for a hostname",
      inputSchema: {
        type: "object",
        properties: {
          host: { type: "string", description: "Hostname to lookup" },
          server: { type: "string", description: "DNS server to query" },
          type: { type: "string", description: "Query type (A, AAAA, MX, NS, etc.)" }
        },
        required: ["host"]
      }
    },
    {
      name: "netstat",
      description: "Display network connections and statistics",
      inputSchema: {
        type: "object",
        properties: {
          options: { type: "string", description: "Options (e.g., '-an', '-r')" }
        }
      }
    },
    {
      name: "telnet",
      description: "Test TCP connection to host:port",
      inputSchema: {
        type: "object",
        properties: {
          host: { type: "string", description: "Hostname or IP" },
          port: { type: "number", description: "Port number" },
          timeout: { type: "number", description: "Connection timeout in seconds (default: 5)" }
        },
        required: ["host", "port"]
      }
    },
    {
      name: "ssh",
      description: "Execute SSH command",
      inputSchema: {
        type: "object",
        properties: {
          host: { type: "string", description: "SSH host" },
          command: { type: "string", description: "Command to execute" },
          user: { type: "string", description: "Username" },
          port: { type: "number", description: "SSH port (default: 22)" },
          identityFile: { type: "string", description: "Path to private key file" },
          timeout: { type: "number", description: "Connection timeout in seconds" }
        },
        required: ["host", "command"]
      }
    },
    {
      name: "traceroute",
      description: "Trace route to host",
      inputSchema: {
        type: "object",
        properties: {
          host: { type: "string", description: "Hostname or IP address" },
          maxHops: { type: "number", description: "Maximum hops (default: 30)" },
          timeout: { type: "number", description: "Timeout per hop in seconds" }
        },
        required: ["host"]
      }
    },
    {
      name: "curl",
      description: "HTTP request to URL",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "URL to request" },
          method: { type: "string", description: "HTTP method (GET, POST, etc.)" },
          headers: { type: "string", description: "Headers as JSON string" },
          data: { type: "string", description: "Request body" },
          timeout: { type: "number", description: "Timeout in seconds" },
          followRedirects: { type: "boolean", description: "Follow redirects (default: true)" }
        },
        required: ["url"]
      }
    },
    {
      name: "wget",
      description: "Download file from URL",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", description: "URL to download" },
          output: { type: "string", description: "Output file path" },
          timeout: { type: "number", description: "Timeout in seconds" },
          tries: { type: "number", description: "Number of retries" }
        },
        required: ["url"]
      }
    },
    {
      name: "whois",
      description: "WHOIS lookup for domain",
      inputSchema: {
        type: "object",
        properties: {
          domain: { type: "string", description: "Domain name or IP" }
        },
        required: ["domain"]
      }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const params = args as Record<string, any>;

  try {
    let cmd = "";
    
    switch (name) {
      case "ping":
        if (!validateHost(params.host)) throw new Error("Invalid host");
        const count = Math.min(Math.max(1, params.count || 4), 100);
        let pingOpts = "";
        if (process.platform === "win32") {
          pingOpts = `-n ${count}`;
          if (params.timeout) pingOpts += ` -w ${Math.min(params.timeout * 1000, 60000)}`;
          if (params.packetSize) pingOpts += ` -l ${Math.min(params.packetSize, 65500)}`;
          if (params.ttl) pingOpts += ` -i ${Math.min(params.ttl, 255)}`;
          cmd = `ping ${pingOpts} ${params.host}`;
        } else {
          pingOpts = `-c ${count}`;
          if (params.timeout) pingOpts += ` -W ${Math.min(params.timeout, 60)}`;
          if (params.packetSize) pingOpts += ` -s ${Math.min(params.packetSize, 65500)}`;
          if (params.ttl) pingOpts += ` -t ${Math.min(params.ttl, 255)}`;
          cmd = `ping ${pingOpts} ${params.host}`;
        }
        break;
      
      case "nslookup":
        if (!validateHost(params.host)) throw new Error("Invalid host");
        if (params.server && !validateHost(params.server)) throw new Error("Invalid DNS server");
        const allowedTypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"];
        let nslookupCmd = "";
        if (params.type) {
          if (!allowedTypes.includes(params.type.toUpperCase())) throw new Error("Invalid query type");
          nslookupCmd = `-type=${params.type} `;
        }
        nslookupCmd += params.host;
        if (params.server) nslookupCmd += ` ${params.server}`;
        cmd = `nslookup ${nslookupCmd}`;
        break;
      
      case "netstat":
        const allowedOptions = ["-a", "-n", "-r", "-s", "-an", "-rn", "-ano", "-e", ""];
        const opts = params.options || "";
        if (!allowedOptions.includes(opts)) throw new Error("Invalid netstat options");
        cmd = `netstat ${opts}`;
        break;
      
      case "telnet":
        if (!validateHost(params.host)) throw new Error("Invalid host");
        if (params.port < 1 || params.port > 65535) throw new Error("Invalid port");
        const telnetTimeout = Math.min(params.timeout || 5, 60);
        cmd = process.platform === "win32"
          ? `powershell -Command "Test-NetConnection -ComputerName ${params.host} -Port ${params.port}"`
          : `timeout ${telnetTimeout} telnet ${params.host} ${params.port}`;
        break;
      
      case "ssh":
        if (!validateHost(params.host)) throw new Error("Invalid host");
        if (params.user && !/^[a-zA-Z0-9_-]+$/.test(params.user)) throw new Error("Invalid username");
        if (params.port && (params.port < 1 || params.port > 65535)) throw new Error("Invalid port");
        if (params.identityFile && !validatePath(params.identityFile)) throw new Error("Invalid identity file path");
        const user = params.user ? `${params.user}@` : "";
        let sshOpts = "-o StrictHostKeyChecking=no ";
        if (params.port) sshOpts += `-p ${params.port} `;
        if (params.identityFile) sshOpts += `-i ${params.identityFile} `;
        if (params.timeout) sshOpts += `-o ConnectTimeout=${Math.min(params.timeout, 60)} `;
        const safeCommand = params.command.replace(/"/g, '\\"');
        cmd = `ssh ${sshOpts}${user}${params.host} "${safeCommand}"`;
        break;
      
      case "traceroute":
        if (!validateHost(params.host)) throw new Error("Invalid host");
        const maxHops = Math.min(params.maxHops || 30, 64);
        if (process.platform === "win32") {
          let traceOpts = `-h ${maxHops}`;
          if (params.timeout) traceOpts += ` -w ${Math.min(params.timeout * 1000, 60000)}`;
          cmd = `tracert ${traceOpts} ${params.host}`;
        } else {
          let traceOpts = `-m ${maxHops}`;
          if (params.timeout) traceOpts += ` -w ${Math.min(params.timeout, 60)}`;
          cmd = `traceroute ${traceOpts} ${params.host}`;
        }
        break;
      
      case "curl":
        if (!validateUrl(params.url)) throw new Error("Invalid URL");
        const allowedMethods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
        let curlOpts = "";
        if (params.method) {
          if (!allowedMethods.includes(params.method.toUpperCase())) throw new Error("Invalid HTTP method");
          curlOpts += `-X ${params.method.toUpperCase()} `;
        }
        if (params.headers) {
          const headers = JSON.parse(params.headers);
          Object.entries(headers).forEach(([k, v]) => {
            const safeKey = sanitizeInput(String(k));
            const safeVal = sanitizeInput(String(v));
            curlOpts += `-H "${safeKey}: ${safeVal}" `;
          });
        }
        if (params.data) curlOpts += `-d '${params.data.replace(/'/g, "'\\''")}' `;
        if (params.timeout) curlOpts += `--max-time ${Math.min(params.timeout, 300)} `;
        if (params.followRedirects !== false) curlOpts += `-L `;
        cmd = `curl ${curlOpts}"${params.url}"`;
        break;
      
      case "wget":
        if (!validateUrl(params.url)) throw new Error("Invalid URL");
        if (params.output && !validatePath(params.output)) throw new Error("Invalid output path");
        let wgetOpts = "";
        if (params.output) wgetOpts += `-O ${params.output} `;
        if (params.timeout) wgetOpts += `--timeout=${Math.min(params.timeout, 300)} `;
        if (params.tries) wgetOpts += `--tries=${Math.min(params.tries, 10)} `;
        cmd = process.platform === "win32"
          ? `powershell -Command "Invoke-WebRequest -Uri '${params.url}' ${params.output ? `-OutFile '${params.output}'` : ''}"`
          : `wget ${wgetOpts}"${params.url}"`;
        break;
      
      case "whois":
        if (!validateDomain(params.domain)) throw new Error("Invalid domain");
        cmd = `whois ${params.domain}`;
        break;
      
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    const { stdout, stderr } = await execAsync(cmd);
    return {
      content: [{ type: "text", text: stdout || stderr }]
    };
  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}\n${error.stderr || ""}` }],
      isError: true
    };
  }
});

const transport = new StdioServerTransport();
server.connect(transport).catch(console.error);
