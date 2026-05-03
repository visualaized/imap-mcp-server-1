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

// Shared services
const accountManager = new AccountManager();
const imapService = new ImapService();
const smtpService = new SmtpService();
const spamService = new SpamService();
imapService.setAccountManager(accountManager);

async function setupFromEnv(): Promise<void> {
  const { IMAP_HOST, IMAP_USER, IMAP_PASSWORD, IMAP_PORT, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD } = process.env;
  if (!IMAP_HOST || !IMAP_USER || !IMAP_PASSWORD) return;

  const existing = accountManager.getAllAccounts();
  if (existing.some(a => a.user === IMAP_USER)) return;

  await accountManager.addAccount({
    name: IMAP_USER,
    host: IMAP_HOST,
    port: parseInt(IMAP_PORT || '993'),
    user: IMAP_USER,
    password: IMAP_PASSWORD,
    tls: true,
    smtp: SMTP_HOST ? {
      host: SMTP_HOST,
      port: parseInt(SMTP_PORT || '587'),
      secure: parseInt(SMTP_PORT || '587') === 465,
      user: SMTP_USER || IMAP_USER,
      password: SMTP_PASSWORD || IMAP_PASSWORD,
    } : undefined,
  });

  console.error(`Auto-configured IMAP account: ${IMAP_USER}`);
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

// Auth middleware
app.use('/mcp', (req, res, next) => {
  if (!AUTH_TOKEN) return next();
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token !== AUTH_TOKEN) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
});

// New or existing session
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

// SSE stream for existing session
app.get('/mcp', async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string;
  const transport = sessions.get(sessionId);
  if (!transport) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }
  await transport.handleRequest(req, res);
});

// Close session
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
  });
});
