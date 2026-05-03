import express from 'express';
import cors from 'cors';
import { randomUUID } from 'crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import dotenv from 'dotenv';
import { ImapService } from './services/imap-service.js';
import { AccountManager } from './services/account-manager.js';
import { SmtpService } from './services/smtp-service.js';
import { SpamService } from './services/spam-service.js';
import { registerTools } from './tools/index.js';

dotenv.config();

const PORT = parseInt(process.env.PORT || '3000');
const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN;
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID;
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET;

// Shared services
const accountManager = new AccountManager();
const imapService = new ImapService();
const smtpService = new SmtpService();
const spamService = new SpamService();
imapService.setAccountManager(accountManager);

async function setupAccountFromVars(
  imapHost: string, imapUser: string, imapPassword: string,
  imapPort?: string, smtpHost?: string, smtpPort?: string,
  smtpUser?: string, smtpPassword?: string
): Promise<void> {
  const existing = accountManager.getAllAccounts();
  if (existing.some(a => a.user === imapUser)) return;

  await accountManager.addAccount({
    name: imapUser,
    host: imapHost,
    port: parseInt(imapPort || '993'),
    user: imapUser,
    password: imapPassword,
    tls: true,
    smtp: smtpHost ? {
      host: smtpHost,
      port: parseInt(smtpPort || '587'),
      secure: parseInt(smtpPort || '587') === 465,
      user: smtpUser || imapUser,
      password: smtpPassword || imapPassword,
    } : undefined,
  });

  console.error(`Auto-configured IMAP account: ${imapUser}`);
}

async function setupFromEnv(): Promise<void> {
  const env = process.env;

  if (env.IMAP_HOST && env.IMAP_USER && env.IMAP_PASSWORD) {
    await setupAccountFromVars(
      env.IMAP_HOST, env.IMAP_USER, env.IMAP_PASSWORD,
      env.IMAP_PORT, env.SMTP_HOST, env.SMTP_PORT, env.SMTP_USER, env.SMTP_PASSWORD
    );
  }

  for (let i = 1; ; i++) {
    const host = env[`IMAP_HOST_${i}`];
    const user = env[`IMAP_USER_${i}`];
    const password = env[`IMAP_PASSWORD_${i}`];
    if (!host || !user || !password) break;

    await setupAccountFromVars(
      host, user, password,
      env[`IMAP_PORT_${i}`], env[`SMTP_HOST_${i}`],
      env[`SMTP_PORT_${i}`], env[`SMTP_USER_${i}`], env[`SMTP_PASSWORD_${i}`]
    );
  }
}

function isValidToken(token: string | undefined): boolean {
  if (!token) return false;
  if (AUTH_TOKEN && token === AUTH_TOKEN) return true;
  return false;
}

function createMcpServer(): McpServer {
  const server = new McpServer({ name: 'imap-mcp-server', version: '1.0.0' });
  registerTools(server, imapService, accountManager, smtpService, spamService);
  return server;
}

const sessions = new Map<string, StreamableHTTPServerTransport>();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── OAuth 2.0 ────────────────────────────────────────────────────────────────

// Discovery endpoint (RFC 8414)
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  res.json({
    issuer: base,
    token_endpoint: `${base}/token`,
    grant_types_supported: ['client_credentials'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  });
});

// Token endpoint — client_credentials grant
app.post('/token', (req, res) => {
  let clientId: string | undefined;
  let clientSecret: string | undefined;

  // Support Basic auth header
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Basic ')) {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString();
    const sep = decoded.indexOf(':');
    clientId = decoded.slice(0, sep);
    clientSecret = decoded.slice(sep + 1);
  } else {
    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const grantType = req.body.grant_type;

  if (grantType !== 'client_credentials') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }

  if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
    res.status(500).json({ error: 'server_error', error_description: 'OAuth not configured on server' });
    return;
  }

  if (clientId !== OAUTH_CLIENT_ID || clientSecret !== OAUTH_CLIENT_SECRET) {
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  res.json({
    access_token: AUTH_TOKEN,
    token_type: 'Bearer',
    expires_in: 31536000,
  });
});

// ─── MCP Auth middleware ───────────────────────────────────────────────────────

app.use('/mcp', (req, res, next) => {
  if (!AUTH_TOKEN) return next();
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!isValidToken(token)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
});

// ─── MCP Endpoints ────────────────────────────────────────────────────────────

app.post('/mcp', async (req, res) => {
  const incomingId = req.headers['mcp-session-id'] as string | undefined;

  if (incomingId && sessions.has(incomingId)) {
    await sessions.get(incomingId)!.handleRequest(req, res, req.body);
    return;
  }

  const sessionId = randomUUID();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
  });

  sessions.set(sessionId, transport);
  transport.onclose = () => sessions.delete(sessionId);

  const server = createMcpServer();
  await server.connect(transport);
  await transport.handleRequest(req, res, req.body);
});

app.get('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string;
  const transport = sessions.get(sessionId);
  if (!transport) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  await transport.handleRequest(req, res);
});

app.delete('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string;
  const transport = sessions.get(sessionId);
  if (transport) {
    await transport.close();
    sessions.delete(sessionId);
  }
  res.status(204).end();
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', sessions: sessions.size });
});

setupFromEnv().then(() => {
  app.listen(PORT, () => {
    console.error(`IMAP MCP Server (HTTP) running on port ${PORT}`);
    if (!AUTH_TOKEN) console.warn('Warning: MCP_AUTH_TOKEN not set — endpoint is unprotected');
    if (!OAUTH_CLIENT_ID) console.warn('Warning: OAUTH_CLIENT_ID not set — OAuth disabled');
  });
});
