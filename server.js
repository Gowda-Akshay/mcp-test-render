const express = require("express");
const crypto = require("crypto");
const { z } = require("zod");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const {
  StreamableHTTPServerTransport,
} = require("@modelcontextprotocol/sdk/server/streamableHttp.js");

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 3000);
const VALID_BEARER_TOKEN = process.env.MCP_BEARER_TOKEN || "test-m2m-token";
const REQUIRED_SCOPE = process.env.REQUIRED_SCOPE || "mcp:tools";
const issuedTokenScopes = new Map();

function parseScopes(scopeValue) {
  return String(scopeValue || "")
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

issuedTokenScopes.set(
  VALID_BEARER_TOKEN,
  new Set(parseScopes(process.env.MCP_BEARER_TOKEN_SCOPES || REQUIRED_SCOPE))
);

function requireBearerToken(req, res, next) {
  const auth = req.headers.authorization || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({
      error: "invalid_token",
      error_description: "Missing bearer token",
    });
  }

  const token = match[1].trim();
  const scopes = issuedTokenScopes.get(token);
  if (!scopes) {
    return res.status(401).json({
      error: "invalid_token",
      error_description: "Bad bearer token",
    });
  }
  if (!scopes.has(REQUIRED_SCOPE)) {
    return res.status(403).json({
      error: "insufficient_scope",
      error_description: `Token must include scope: ${REQUIRED_SCOPE}`,
    });
  }

  next();
}

app.post("/oauth/token", express.urlencoded({ extended: false }), (req, res) => {
  const { grant_type, client_id, client_secret, scope } = req.body;

  const expectedClientId = process.env.OAUTH_CLIENT_ID || "demo-client";
  const expectedClientSecret = process.env.OAUTH_CLIENT_SECRET || "demo-secret";

  if (grant_type !== "client_credentials") {
    return res.status(400).json({ error: "unsupported_grant_type" });
  }

  if (client_id !== expectedClientId || client_secret !== expectedClientSecret) {
    return res.status(401).json({ error: "invalid_client" });
  }

  const requestedScopes = parseScopes(scope);
  if (requestedScopes.length === 0) {
    return res.status(400).json({
      error: "invalid_scope",
      error_description: "Scope is required",
    });
  }
  if (!requestedScopes.includes(REQUIRED_SCOPE)) {
    return res.status(400).json({
      error: "invalid_scope",
      error_description: `Requested scope must include: ${REQUIRED_SCOPE}`,
    });
  }

  const accessToken = crypto.randomUUID();
  issuedTokenScopes.set(accessToken, new Set(requestedScopes));

  return res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: requestedScopes.join(" "),
  });
});

app.get("/.well-known/oauth-protected-resource", (req, res) => {
  const forwardedProto = req.headers["x-forwarded-proto"];
  const protocol = (typeof forwardedProto === "string" ? forwardedProto : req.protocol) || "http";
  const host = req.get("host") || `localhost:${PORT}`;
  const dynamicBase = `${protocol}://${host}`;
  const baseUrl = process.env.PUBLIC_BASE_URL || dynamicBase;
  res.json({
    resource: `${baseUrl}/health`,
    authorization_servers: [baseUrl],
  });
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "demo-m2m-mcp" });
});

function createMcpServer() {
  const server = new McpServer({
    name: "demo-m2m-mcp",
    version: "1.0.0",
  });

  server.registerTool(
    "ping",
    {
      title: "Ping",
      description: "Returns pong",
      inputSchema: {},
    },
    async () => ({
      content: [{ type: "text", text: "pong - MCP server is alive and responding." }],
    })
  );

  server.registerTool(
    "add",
    {
      title: "Add",
      description: "Add two numbers",
      inputSchema: {
        a: z.number(),
        b: z.number(),
      },
    },
    async ({ a, b }) => ({
      content: [{ type: "text", text: String(a + b) }],
    })
  );

  server.registerTool(
    "get_hardcoded_data",
    {
      title: "Get Hardcoded Data",
      description: "Returns a fixed hardcoded payload for testing",
      inputSchema: {},
    },
    async () => ({
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              source: "demo-m2m-mcp",
              status: "ok",
              message: "This is hardcoded test data.",
              items: [
                { id: 1, name: "alpha" },
                { id: 2, name: "beta" },
                { id: 3, name: "gamma" },
              ],
            },
            null,
            2
          ),
        },
      ],
    })
  );

  return server;
}

async function handleMcp(req, res) {
  try {
    const server = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    res.on("close", () => {
      transport.close();
      server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (err) {
    console.error("MCP error:", err);
    if (!res.headersSent) {
      res.status(500).json({
        error: "server_error",
        error_description: "MCP request failed",
      });
    }
  }
}

// Primary MCP endpoint
app.all("/mcp", requireBearerToken, handleMcp);
// Render fallback endpoint: POST /health for MCP, while GET /health stays health check
app.post("/health", requireBearerToken, handleMcp);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Health:    http://localhost:${PORT}/health`);
  console.log(`Token URL: http://localhost:${PORT}/oauth/token`);
  console.log(`MCP URL:   http://localhost:${PORT}/mcp`);
});
