#!/usr/bin/env node
import express from "express";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);
const app = express();
app.use(express.json());

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

const executeTool = async (name: string, params: Record<string, any>) => {

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
    return { result: stdout || stderr };
  } catch (error: any) {
    throw new Error(`${error.message}\n${error.stderr || ""}`);
  }
};

app.get("/openapi.json", (req, res) => {
  res.json({
    openapi: "3.0.0",
    info: {
      title: "Net Tools API",
      version: "1.0.0",
      description: "HTTP-based network diagnostic tools API"
    },
    servers: [{ url: "http://localhost:3000" }],
    paths: {
      "/ping": {
        post: {
          summary: "Ping a host",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["host"],
                  properties: {
                    host: { type: "string", description: "Hostname or IP address" },
                    count: { type: "number", description: "Number of packets" },
                    timeout: { type: "number", description: "Timeout in seconds" },
                    packetSize: { type: "number", description: "Packet size in bytes" },
                    ttl: { type: "number", description: "Time to live" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/nslookup": {
        post: {
          summary: "DNS lookup",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["host"],
                  properties: {
                    host: { type: "string", description: "Hostname to lookup" },
                    server: { type: "string", description: "DNS server" },
                    type: { type: "string", description: "Query type (A, AAAA, MX, etc.)" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/netstat": {
        post: {
          summary: "Network statistics",
          requestBody: {
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    options: { type: "string", description: "Options (e.g., '-an')" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/telnet": {
        post: {
          summary: "Test TCP port",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["host", "port"],
                  properties: {
                    host: { type: "string", description: "Hostname or IP" },
                    port: { type: "number", description: "Port number" },
                    timeout: { type: "number", description: "Timeout in seconds" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/ssh": {
        post: {
          summary: "Execute SSH command",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["host", "command"],
                  properties: {
                    host: { type: "string", description: "SSH host" },
                    command: { type: "string", description: "Command to execute" },
                    user: { type: "string", description: "Username" },
                    port: { type: "number", description: "SSH port" },
                    identityFile: { type: "string", description: "Private key path" },
                    timeout: { type: "number", description: "Timeout in seconds" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/traceroute": {
        post: {
          summary: "Trace route to host",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["host"],
                  properties: {
                    host: { type: "string", description: "Hostname or IP" },
                    maxHops: { type: "number", description: "Maximum hops" },
                    timeout: { type: "number", description: "Timeout per hop" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/curl": {
        post: {
          summary: "HTTP request",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["url"],
                  properties: {
                    url: { type: "string", description: "URL to request" },
                    method: { type: "string", description: "HTTP method" },
                    headers: { type: "string", description: "Headers as JSON string" },
                    data: { type: "string", description: "Request body" },
                    timeout: { type: "number", description: "Timeout in seconds" },
                    followRedirects: { type: "boolean", description: "Follow redirects" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/wget": {
        post: {
          summary: "Download file",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["url"],
                  properties: {
                    url: { type: "string", description: "URL to download" },
                    output: { type: "string", description: "Output file path" },
                    timeout: { type: "number", description: "Timeout in seconds" },
                    tries: { type: "number", description: "Number of retries" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      },
      "/whois": {
        post: {
          summary: "WHOIS lookup",
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["domain"],
                  properties: {
                    domain: { type: "string", description: "Domain name or IP" }
                  }
                }
              }
            }
          },
          responses: {
            "200": { description: "Success", content: { "application/json": { schema: { type: "object", properties: { result: { type: "string" } } } } } },
            "500": { description: "Error", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } }
          }
        }
      }
    }
  });
});

const tools = ["ping", "nslookup", "netstat", "telnet", "ssh", "traceroute", "curl", "wget", "whois"];
tools.forEach(tool => {
  app.post(`/${tool}`, async (req, res) => {
    try {
      const result = await executeTool(tool, req.body);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
