import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express, { Request, Response } from "express";
import { z } from "zod";
import chalk from "chalk";
import { runCheckPackage, runCheckSbom } from "./tools.js";

// ============================================================================
// Dev Logging Utilities
// ============================================================================

const isDev = process.env.NODE_ENV !== "production";

function timestamp(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function formatLatency(ms: number): string {
  if (ms < 100) return chalk.green(`${ms}ms`);
  if (ms < 500) return chalk.yellow(`${ms}ms`);
  return chalk.red(`${ms}ms`);
}

function truncate(str: string, maxLen = 60): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + "...";
}

function logRequest(method: string, params?: unknown): void {
  if (!isDev) return;

  const paramsStr = params ? chalk.gray(` ${truncate(JSON.stringify(params))}`) : "";
  console.log(`${chalk.gray(`[${timestamp()}]`)} ${chalk.cyan("→")} ${method}${paramsStr}`);
}

function logResponse(method: string, result: unknown, latencyMs: number): void {
  if (!isDev) return;

  const latency = formatLatency(latencyMs);

  // For tool calls, show the result
  if (method === "tools/call" && result) {
    const resultStr = typeof result === "string" ? result : JSON.stringify(result);
    console.log(
      `${chalk.gray(`[${timestamp()}]`)} ${chalk.green("←")} ${truncate(resultStr)} ${chalk.gray(`(${latency})`)}`
    );
  } else {
    console.log(`${chalk.gray(`[${timestamp()}]`)} ${chalk.green("✓")} ${method} ${chalk.gray(`(${latency})`)}`);
  }
}

function logError(method: string, error: unknown, latencyMs: number): void {
  const latency = formatLatency(latencyMs);

  let errorMsg: string;
  if (error instanceof Error) {
    errorMsg = error.message;
  } else if (typeof error === "object" && error !== null) {
    // JSON-RPC error object has { code, message, data? }
    const rpcError = error as { message?: string; code?: number };
    errorMsg = rpcError.message || `Error ${rpcError.code || "unknown"}`;
  } else {
    errorMsg = String(error);
  }

  console.log(
    `${chalk.gray(`[${timestamp()}]`)} ${chalk.red("✖")} ${method} ${chalk.red(truncate(errorMsg))} ${chalk.gray(`(${latency})`)}`
  );
}

// ============================================================================
// MCP Server Setup
// ============================================================================

// Build a FRESH MCP server per request.
//
// In stateless streamable-HTTP mode the MCP SDK allows a Server to be connected
// to exactly ONE transport. Reusing a single module-scope instance throws
// "Already connected to a transport" on the second connection — and Cloud Run
// opens several (startup probe + real requests). So always create a new server
// (and a new transport) inside the request handler below.
function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "dep-vuln-check",
    version: "1.0.0",
  });

  // check_package: single package vulnerability lookup via OSV.dev
  server.registerTool(
    "check_package",
    {
      title: "Check Package Vulnerabilities",
      description:
        "Check whether a specific package version has known vulnerabilities, using the OSV.dev database (free, no API key). Returns each vulnerability's ID, summary, severity, CVSS score when available, fixed versions, and publication date. Results are cached for 10 minutes.",
      inputSchema: {
        ecosystem: z
          .string()
          .describe(
            "Package ecosystem (OSV name), one of: npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems, Hex, pub. Case-insensitive."
          ),
        name: z
          .string()
          .describe("Exact package name in its ecosystem, e.g. 'lodash' (npm), 'requests' (PyPI), 'serde' (crates.io)."),
        version: z
          .string()
          .describe("Exact version string to check, e.g. '4.17.20'. Must match a published version; unknown versions return no vulnerabilities."),
      },
      outputSchema: {
        package: z.string(),
        ecosystem: z.string(),
        version: z.string(),
        vulnerable: z.boolean(),
        cached: z.boolean(),
        vulns: z.array(
          z.object({
            id: z.string(),
            summary: z.string(),
            severity: z.string(),
            cvss_score: z.number().nullable(),
            fixed_versions: z.array(z.string()),
            published: z.string().nullable(),
          })
        ),
      },
    },
    async ({ ecosystem, name, version }) => {
      return await runCheckPackage({ ecosystem, name, version });
    }
  );

  // check_sbom: scan up to 50 packages in one call
  server.registerTool(
    "check_sbom",
    {
      title: "Scan SBOM for Vulnerabilities",
      description:
        "Scan a software bill of materials (list of up to 50 packages with ecosystem, name, and version) for known vulnerabilities via OSV.dev. Returns per-package results plus totals. Unknown packages return empty vulnerability lists (not errors). Results are cached for 10 minutes.",
      inputSchema: {
        packages: z
          .array(
            z.object({
              ecosystem: z
                .string()
                .describe("Package ecosystem (OSV name): npm, PyPI, Go, crates.io, Maven, NuGet, Packagist, RubyGems, Hex, pub."),
              name: z.string().describe("Exact package name in its ecosystem."),
              version: z.string().describe("Exact version string to check."),
            })
          )
          .min(1)
          .max(50)
          .describe("Packages to scan (1-50). Each object needs ecosystem, name, and version."),
      },
      outputSchema: {
        scanned: z.number(),
        vulnerable_count: z.number(),
        cached_results: z.number(),
        results: z.array(
          z.object({
            package: z.string(),
            ecosystem: z.string(),
            version: z.string(),
            vulnerable: z.boolean(),
            cached: z.boolean(),
            vulns: z.array(
              z.object({
                id: z.string(),
                summary: z.string(),
                severity: z.string(),
                cvss_score: z.number().nullable(),
                fixed_versions: z.array(z.string()),
                published: z.string().nullable(),
              })
            ),
            vulns_truncated: z.boolean(),
          })
        ),
      },
    },
    async ({ packages }) => {
      return await runCheckSbom({ packages });
    }
  );

  return server;
}

// ============================================================================
// Express App Setup
// ============================================================================

const app = express();
app.use(express.json());

// Health check endpoint (required for Cloud Run)
app.get("/health", (_req: Request, res: Response) => {
  res.status(200).json({ status: "healthy" });
});

// MCP endpoint with dev logging
app.post("/mcp", async (req: Request, res: Response) => {
  const startTime = Date.now();
  const body = req.body;

  // Extract method and params from JSON-RPC request
  const method = body?.method || "unknown";
  const params = body?.params;

  // Log incoming request
  if (method === "tools/call") {
    const toolName = params?.name || "unknown";
    const toolArgs = params?.arguments;
    logRequest(`tools/call ${chalk.bold(toolName)}`, toolArgs);
  } else if (method !== "notifications/initialized") {
    logRequest(method, params);
  }

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  // Capture response body for logging
  let responseBody = "";
  const originalWrite = res.write.bind(res) as typeof res.write;
  const originalEnd = res.end.bind(res) as typeof res.end;

  res.write = function (chunk: unknown, encodingOrCallback?: BufferEncoding | ((error: Error | null | undefined) => void), callback?: (error: Error | null | undefined) => void) {
    if (chunk) {
      responseBody += typeof chunk === "string" ? chunk : Buffer.from(chunk as ArrayBuffer).toString();
    }
    return originalWrite(chunk as string, encodingOrCallback as BufferEncoding, callback);
  };

  res.end = function (chunk?: unknown, encodingOrCallback?: BufferEncoding | (() => void), callback?: () => void) {
    if (chunk) {
      responseBody += typeof chunk === "string" ? chunk : Buffer.from(chunk as ArrayBuffer).toString();
    }

    // Log response
    if (method !== "notifications/initialized") {
      const latency = Date.now() - startTime;

      try {
        const rpcResponse = JSON.parse(responseBody) as { result?: unknown; error?: unknown };

        if (rpcResponse?.error) {
          logError(method, rpcResponse.error, latency);
        } else if (method === "tools/call") {
          const content = (rpcResponse?.result as { content?: Array<{ text?: string }> })?.content;
          const resultText = content?.[0]?.text;
          logResponse(method, resultText, latency);
        } else {
          logResponse(method, null, latency);
        }
      } catch {
        logResponse(method, null, latency);
      }
    }

    return originalEnd(chunk as string, encodingOrCallback as BufferEncoding, callback);
  };

  res.on("close", () => {
    transport.close();
  });

  // Fresh server instance per request (see createMcpServer above) — required for
  // stateless streamable-HTTP so a second connection never reuses a transport.
  const server = createMcpServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

// JSON error handler (Express defaults to HTML errors)
app.use((_err: unknown, _req: Request, res: Response, _next: Function) => {
  res.status(500).json({ error: "Internal server error" });
});

// ============================================================================
// Start Server
// ============================================================================

const port = parseInt(process.env.PORT || "8080");
const httpServer = app.listen(port, () => {
  console.log();
  console.log(chalk.bold("MCP Server running on"), chalk.cyan(`http://localhost:${port}`));
  console.log(`  ${chalk.gray("Health:")} http://localhost:${port}/health`);
  console.log(`  ${chalk.gray("MCP:")}    http://localhost:${port}/mcp`);

  if (isDev) {
    console.log();
    console.log(chalk.gray("─".repeat(50)));
    console.log();
  }
});

// Graceful shutdown for Cloud Run (SIGTERM before kill)
process.on("SIGTERM", () => {
  console.log("Received SIGTERM, shutting down...");
  httpServer.close(() => {
    process.exit(0);
  });
});
