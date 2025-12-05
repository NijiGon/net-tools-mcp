#!/usr/bin/env ts-node
import "dotenv/config";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";
import { promisify } from "util";
import { exec } from "child_process";

// Create MCP server
const server = new McpServer(
  { name: "my-sse-mcp", version: "1.0.0" },
  { capabilities: {} }
);

const execAsync = promisify(exec);
const runCommand = async (cmd: string) => {
  const { stdout, stderr } = await execAsync(cmd);
  return stdout || stderr;
};

// Ping
server.registerTool(
  "ping",
  {
    description: "Ping a host to check connectivity",
    inputSchema: z.object({
      host: z.string().regex(/^[a-zA-Z0-9.-]+$/).describe("Target hostname or IP address"),
      count: z.number().int().min(1).max(100).optional().describe("Number of ping packets to send (1-100, default: 4)"),
      timeout: z.number().min(1).max(60).optional().describe("Timeout in seconds (1-60)"),
      packetSize: z.number().min(1).max(65500).optional().describe("Packet size in bytes (1-65500)"),
      ttl: z.number().min(1).max(255).optional().describe("Time to live (1-255)"),
    }),
  },
  async ({
    host,
    count = 4,
    timeout,
    packetSize,
    ttl,
  }: {
    host: string;
    count?: number | undefined;
    timeout?: number | undefined;
    packetSize?: number | undefined;
    ttl?: number | undefined;
  }) => {
    const pingOpts =
      process.platform === "win32"
        ? `-n ${count}${timeout ? ` -w ${timeout * 1000}` : ""}${
            packetSize ? ` -l ${packetSize}` : ""
          }${ttl ? ` -i ${ttl}` : ""}`
        : `-c ${count}${timeout ? ` -W ${timeout}` : ""}${
            packetSize ? ` -s ${packetSize}` : ""
          }${ttl ? ` -t ${ttl}` : ""}`;
    const output = await runCommand(`ping ${pingOpts} ${host}`);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// Nslookup
server.registerTool(
  "nslookup",
  {
    description: "DNS lookup for a hostname",
    inputSchema: z.object({
      host: z.string().regex(/^[a-zA-Z0-9.-]+$/).describe("Hostname or IP address to lookup"),
      server: z
        .string()
        .regex(/^[a-zA-Z0-9.-]+$/)
        .optional()
        .describe("DNS server to query"),
      type: z
        .enum(["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"])
        .optional()
        .describe("DNS record type to query"),
    }),
  },
  async ({
    host,
    server: dnsServer,
    type,
  }: {
    host: string;
    server?: string | undefined;
    type?: string | undefined;
  }) => {
    let cmd = `nslookup ${host}`;
    if (type) cmd += ` -type=${type}`;
    if (dnsServer) cmd += ` ${dnsServer}`;
    const output = await runCommand(cmd);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// Netstat
server.registerTool(
  "netstat",
  {
    description: "Display network connections and statistics",
    inputSchema: z.object({
      options: z
        .enum(["-a", "-n", "-r", "-s", "-an", "-rn", "-ano", "-e", ""])
        .optional()
        .describe("Netstat options: -a (all), -n (numeric), -r (routing), -s (statistics), -e (ethernet)"),
    }),
  },
  async ({ options = "" }: { options?: string | undefined }) => {
    const output = await runCommand(`netstat ${options}`);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// Telnet
server.registerTool(
  "telnet",
  {
    description: "Test TCP connection to host:port",
    inputSchema: z.object({
      host: z.string().regex(/^[a-zA-Z0-9.-]+$/).describe("Target hostname or IP address"),
      port: z.number().int().min(1).max(65535).describe("Target port number (1-65535)"),
      timeout: z.number().min(1).max(60).optional().describe("Connection timeout in seconds (1-60, default: 5)"),
    }),
  },
  async ({
    host,
    port,
    timeout = 5,
  }: {
    host: string;
    port: number;
    timeout?: number | undefined;
  }) => {
    const cmd =
      process.platform === "win32"
        ? `powershell -Command "Test-NetConnection -ComputerName ${host} -Port ${port}"`
        : `timeout ${timeout} telnet ${host} ${port}`;
    const output = await runCommand(cmd);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// SSH
server.registerTool(
  "ssh",
  {
    description: "Execute SSH command",
    inputSchema: z.object({
      host: z.string().regex(/^[a-zA-Z0-9.-]+$/).describe("Target hostname or IP address"),
      command: z.string().describe("Command to execute on remote host"),
      user: z
        .string()
        .regex(/^[a-zA-Z0-9_-]+$/)
        .optional()
        .describe("SSH username"),
      port: z.number().int().min(1).max(65535).optional().describe("SSH port (default: 22)"),
      identityFile: z
        .string()
        .regex(/^[a-zA-Z0-9._\/-]+$/)
        .optional()
        .describe("Path to SSH private key file"),
      timeout: z.number().min(1).max(60).optional().describe("Connection timeout in seconds (1-60)"),
    }),
  },
  async ({
    host,
    command,
    user,
    port,
    identityFile,
    timeout,
  }: {
    host: string;
    command: string;
    user?: string | undefined;
    port?: number | undefined;
    identityFile?: string | undefined;
    timeout?: number | undefined;
  }) => {
    const userPrefix = user ? `${user}@` : "";
    let sshOpts = "-o StrictHostKeyChecking=no ";
    if (port) sshOpts += `-p ${port} `;
    if (identityFile) sshOpts += `-i ${identityFile} `;
    if (timeout) sshOpts += `-o ConnectTimeout=${timeout} `;
    const safeCommand = command.replace(/"/g, '\\"');
    const output = await runCommand(
      `ssh ${sshOpts}${userPrefix}${host} "${safeCommand}"`
    );
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// Traceroute
server.registerTool(
  "traceroute",
  {
    description: "Trace route to host",
    inputSchema: z.object({
      host: z.string().regex(/^[a-zA-Z0-9.-]+$/).describe("Target hostname or IP address"),
      maxHops: z.number().int().min(1).max(64).optional().describe("Maximum number of hops (1-64, default: 30)"),
      timeout: z.number().min(1).max(60).optional().describe("Timeout per hop in seconds (1-60, default: 5)"),
    }),
  },
  async ({
    host,
    maxHops = 30,
    timeout = 5,
  }: {
    host: string;
    maxHops?: number | undefined;
    timeout?: number | undefined;
  }) => {
    const cmd =
      process.platform === "win32"
        ? `tracert -h ${maxHops} ${host}`
        : `traceroute -m ${maxHops} -w ${timeout} ${host}`;
    const output = await runCommand(cmd);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// Curl
server.registerTool(
  "curl",
  {
    description: "HTTP request to URL",
    inputSchema: z.object({
      url: z.string().url().describe("Target URL"),
      method: z
        .enum(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
        .optional()
        .describe("HTTP method (default: GET)"),
      headers: z.string().optional().describe("JSON string of headers"),
      data: z.string().optional().describe("Request body data"),
      timeout: z.number().min(1).max(300).optional().describe("Request timeout in seconds (1-300)"),
      followRedirects: z.boolean().optional().describe("Follow redirects (default: true)"),
    }),
  },
  async ({
    url,
    method,
    headers,
    data,
    timeout,
    followRedirects,
  }: {
    url: string;
    method?: string | undefined;
    headers?: string | undefined;
    data?: string | undefined;
    timeout?: number | undefined;
    followRedirects?: boolean | undefined;
  }) => {
    let opts = method ? `-X ${method} ` : "";
    if (headers) {
      const hdrs = JSON.parse(headers);
      Object.entries(hdrs).forEach(([k, v]) => (opts += `-H "${k}: ${v}" `));
    }
    if (data) opts += `-d '${data.replace(/'/g, "'\\''")}' `;
    if (timeout) opts += `--max-time ${timeout} `;
    if (followRedirects !== false) opts += "-L ";
    const output = await runCommand(`curl ${opts}"${url}"`);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// Wget
server.registerTool(
  "wget",
  {
    description: "Download file from URL",
    inputSchema: z.object({
      url: z.string().url().describe("URL to download"),
      output: z
        .string()
        .regex(/^[a-zA-Z0-9._\/-]+$/)
        .optional()
        .describe("Output filename"),
      timeout: z.number().min(1).max(300).optional().describe("Download timeout in seconds (1-300)"),
      tries: z.number().min(1).max(10).optional().describe("Number of retry attempts (1-10)"),
    }),
  },
  async ({
    url,
    output,
    timeout,
    tries,
  }: {
    url: string;
    output?: string | undefined;
    timeout?: number | undefined;
    tries?: number | undefined;
  }) => {
    const opts = `${output ? `-O ${output} ` : ""}${
      timeout ? `--timeout=${timeout} ` : ""
    }${tries ? `--tries=${tries} ` : ""}`;
    const cmd =
      process.platform === "win32"
        ? `powershell -Command "Invoke-WebRequest -Uri '${url}' ${
            output ? `-OutFile '${output}'` : ""
          }"`
        : `wget ${opts}"${url}"`;
    const result = await runCommand(cmd);
    return { content: [{ type: "text" as const, text: result }] };
  }
);

// Whois
server.registerTool(
  "whois",
  {
    description: "WHOIS lookup for domain",
    inputSchema: z.object({
      domain: z.string().regex(/^[a-zA-Z0-9.-]+$/).describe("Domain name to lookup"),
    }),
  },
  async ({ domain }: { domain: string }) => {
    const output = await runCommand(`whois ${domain}`);
    return { content: [{ type: "text" as const, text: output }] };
  }
);

// Express app
const app = express();
app.use(express.json());

// API Key middleware
const apiKeyAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
  const apiKey = req.headers["x-api-key"] || req.query.apiKey;
  if (!process.env.API_KEY || apiKey === process.env.API_KEY) {
    next();
  } else {
    res.status(401).json({ error: "Unauthorized" });
  }
};

let transport: SSEServerTransport | null = null;

// Route for SSE MCP
app.get("/mcp", apiKeyAuth, async (req, res) => {
  transport = new SSEServerTransport("/messages", res);
  await server.connect(transport);
});

app.post("/messages", apiKeyAuth, async (req, res) => {
  if (transport) {
    await transport.handlePostMessage(req, res, req.body);
  }
});

// Optional: health check
app.get("/health", (_, res) => res.send("OK"));

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SSE MCP running on port ${PORT}`));
