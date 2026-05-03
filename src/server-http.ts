import express from 'express';
import cors from 'cors';
import { randomUUID, createHash } from 'crypto';
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

// ─── IMAP Account Setup ────────────────────────────────────────────────────────

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

// ─── OAuth State ───────────────────────────────────────────────────────────────

interface AuthCode {
  clientId: string;
  redirectUri: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresAt: number;
}

const authCodes = new Map<string, AuthCode>();

// ─── MCP Server Factory ────────────────────────────────────────────────────────

function createMcpServer(): McpServer {
  const server = new McpServer({ name: 'imap-mcp-server', version: '1.0.0' });
  registerTools(server, imapService, accountManager, smtpService, spamService);
  return server;
}

const sessions = new Map<string, StreamableHTTPServerTransport>();

// ─── Express App ───────────────────────────────────────────────────────────────

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── OAuth Discovery ───────────────────────────────────────────────────────────

app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  res.json({
    issuer: base,
    authorization_endpoint: `${base}/authorize`,
    token_endpoint: `${base}/token`,
    grant_types_supported: ['authorization_code', 'client_credentials'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
  });
});

app.get('/.well-known/oauth-protected-resource', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  res.json({
    resource: `${base}/mcp`,
    authorization_servers: [base],
  });
});

// ─── Authorization Endpoint ────────────────────────────────────────────────────

app.get('/authorize', (req, res) => {
  const {
    response_type, client_id, redirect_uri, state,
    code_challenge, code_challenge_method,
  } = req.query as Record<string, string>;

  if (response_type !== 'code') {
    res.status(400).json({ error: 'unsupported_response_type' });
    return;
  }

  if (OAUTH_CLIENT_ID && client_id !== OAUTH_CLIENT_ID) {
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  if (!redirect_uri) {
    res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uri required' });
    return;
  }

  const code = randomUUID();
  authCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method || 'plain',
    expiresAt: Date.now() + 5 * 60 * 1000,
  });

  // Auto-approve: redirect immediately with code
  const url = new URL(redirect_uri);
  url.searchParams.set('code', code);
  if (state) url.searchParams.set('state', state);

  res.redirect(url.toString());
});

// ─── Token Endpoint ────────────────────────────────────────────────────────────

app.post('/token', (req, res) => {
  let clientId: string | undefined;
  let clientSecret: string | undefined;

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

  // ── Authorization Code Grant ──
  if (grantType === 'authorization_code') {
    const { code, redirect_uri, code_verifier } = req.body;

    const stored = authCodes.get(code);
    if (!stored || Date.now() > stored.expiresAt) {
      authCodes.delete(code);
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }

    if (stored.redirectUri !== redirect_uri) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
      return;
    }

    // Verify PKCE
    if (stored.codeChallenge) {
      if (!code_verifier) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'code_verifier required' });
        return;
      }
      const expected = stored.codeChallengeMethod === 'S256'
        ? createHash('sha256').update(code_verifier).digest('base64url')
        : code_verifier;

      if (expected !== stored.codeChallenge) {
        res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
        return;
      }
    }

    authCodes.delete(code);
    res.json({ access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 31536000 });
    return;
  }

  // ── Client Credentials Grant ──
  if (grantType === 'client_credentials') {
    if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET) {
      res.status(500).json({ error: 'server_error', error_description: 'OAuth not configured' });
      return;
    }
    if (clientId !== OAUTH_CLIENT_ID || clientSecret !== OAUTH_CLIENT_SECRET) {
      res.status(401).json({ error: 'invalid_client' });
      return;
    }
    res.json({ access_token: AUTH_TOKEN, token_type: 'Bearer', expires_in: 31536000 });
    return;
  }

  res.status(400).json({ error: 'unsupported_grant_type' });
});

// ─── MCP Auth Middleware ───────────────────────────────────────────────────────

app.use('/mcp', (req, res, next) => {
  if (!AUTH_TOKEN) return next();
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token !== AUTH_TOKEN) {
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

// ─── Start ─────────────────────────────────────────────────────────────────────

setupFromEnv().then(() => {
  app.listen(PORT, () => {
    console.error(`IMAP MCP Server (HTTP) running on port ${PORT}`);
    if (!AUTH_TOKEN) console.warn('Warning: MCP_AUTH_TOKEN not set — endpoint is unprotected');
    if (!OAUTH_CLIENT_ID) console.warn('Warning: OAUTH_CLIENT_ID not set — OAuth disabled');
  });
});
