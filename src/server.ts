import express, { Response } from "express";
import cors from "cors";
import { randomUUID } from "crypto";
import { promisify } from "util";
import { exec as execCallback } from "child_process";
import fs from "fs/promises";
import { existsSync, mkdirSync } from "fs";
import path from "path";
import AdmZip from "adm-zip";

const exec = promisify(execCallback);

const DEFAULT_NAMESPACE = "vmtool";
const DEFAULT_TIMEOUT = 3600; // seconds
const MAX_OUTPUT = 500_000; // bytes
const SESSION_TIMEOUT = 3600; // seconds
const BASE_PATH = "/mcp";
const EXCLUDED_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "__pycache__",
  ".venv",
  ".mypy_cache",
  ".pytest_cache",
]);

const WORKSPACE = path.resolve(process.env.WORKSPACE || "/app/workspace");
if (!existsSync(WORKSPACE)) {
  mkdirSync(WORKSPACE, { recursive: true });
}

const app = express();
app.use(cors());
app.use(express.json({ limit: "5mb" }));

type ToolDefinition = {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations?: Record<string, unknown>;
};

const TOOLS: ToolDefinition[] = [
  {
    name: "help",
    description: "Show environment info, available commands, and usage examples.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "sh",
    description:
      "Run any shell command (primary tool). Use gh for GitHub. Supports timeout override (t).",
    inputSchema: {
      type: "object",
      properties: {
        c: { type: "string", description: "Command to run" },
        t: { type: "integer", description: "Timeout seconds (default 3600)" },
      },
      required: ["c"],
    },
  },
  {
    name: "write",
    description: "Write content to a file, creating parent directories as needed.",
    inputSchema: {
      type: "object",
      properties: {
        p: { type: "string", description: "File path" },
        c: { type: "string", description: "Content" },
      },
      required: ["p", "c"],
    },
  },
  {
    name: "read",
    description: "Read a file from the workspace.",
    inputSchema: {
      type: "object",
      properties: {
        p: { type: "string", description: "File path" },
      },
      required: ["p"],
    },
  },
  {
    name: "export",
    description: "Export a file or directory (directories are zipped) as base64.",
    inputSchema: {
      type: "object",
      properties: {
        p: { type: "string", description: "File or directory path" },
      },
      required: ["p"],
    },
  },
  {
    name: "repo_map",
    description: "Summarize repository structure with depth and entry limits.",
    inputSchema: {
      type: "object",
      properties: {
        root: { type: "string", description: "Root folder relative to workspace" },
        depth: { type: "integer", description: "Folder depth (default 3)" },
        max_entries: { type: "integer", description: "Maximum entries (default 400)" },
      },
    },
  },
  {
    name: "search_repo",
    description: "Ripgrep-powered search with context lines and glob filters.",
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string", description: "Search pattern" },
        root: { type: "string", description: "Root folder relative to workspace" },
        context: { type: "integer", description: "Context lines (default 2)" },
        max_results: { type: "integer", description: "Max results (default 200)" },
        glob: {
          anyOf: [{ type: "string" }, { type: "array", items: { type: "string" } }],
          description: "Glob filter(s) for ripgrep",
        },
      },
      required: ["q"],
    },
  },
];

function ensureReadOnlyHints() {
  for (const tool of TOOLS) {
    if (!tool.annotations) {
      tool.annotations = {};
    }
    if (tool.annotations.readOnlyHint !== true) {
      tool.annotations.readOnlyHint = true;
    }
  }
}

ensureReadOnlyHints();

interface SessionInfo {
  id: string;
  createdAt: number;
  lastActivity: number;
  messageCount: number;
  response: Response;
  keepAlive: NodeJS.Timeout;
}

const sessions = new Map<string, SessionInfo>();

function sanitizeNamespace(name?: string): string {
  if (!name) return DEFAULT_NAMESPACE;
  return name.trim().replace(/\s+/g, "-").replace(/[\\/]/g, "-") || DEFAULT_NAMESPACE;
}

const namespace = sanitizeNamespace(process.env.VMTOOL_NAMESPACE);

function ensureWorkspacePath(relPath: string): string {
  const resolved = path.resolve(WORKSPACE, relPath);
  if (!resolved.startsWith(WORKSPACE)) {
    throw new Error("Path outside workspace");
  }
  return resolved;
}

function shouldSkip(name: string): boolean {
  return EXCLUDED_DIRS.has(name) || name.startsWith(".");
}

function buildEnvInfo(): string {
  return [
    "# MCP Shell Environment",
    "",
    "## ⚠️ EPHEMERAL SESSION",
    "This environment resets between chat sessions. Clone repos fresh each time.",
    "If the link feels stale, call the **help** tool again to refresh context.",
    "",
    "## Server namespace & tool paths",
    `- Namespace: \`${namespace}\` (set VMTOOL_NAMESPACE to override)`,
    "- Canonical tool paths:",
    `- ${BASE_PATH}/tool/help`,
    `- ${BASE_PATH}/tool/sh`,
    `- ${BASE_PATH}/tool/write`,
    `- ${BASE_PATH}/tool/read`,
    `- ${BASE_PATH}/tool/export`,
    `- ${BASE_PATH}/tool/repo_map`,
    `- ${BASE_PATH}/tool/search_repo`,
    "",
    "## Environment Details",
    "- Timeout: 3600",
    "- OS: Debian",
    "- RAM: 16 GB",
    "- vCPU: 4 core",
    "- CloudSQL (PostGres) attached",
    "",
    "## Workspace",
    `- Location: ${WORKSPACE}`,
    "- All commands run here by default",
    "- Full read/write access",
    "",
    "## Available Tools (use gh for GitHub!)",
    "- gh, git, rg, fd, python, node, gcloud, curl, jq",
  ].join("\n");
}

async function runShell(command: string, timeoutSeconds = DEFAULT_TIMEOUT): Promise<{ code: number; stdout: string; stderr: string }>
{
  try {
    const { stdout, stderr } = await exec(command, { timeout: timeoutSeconds * 1000, cwd: WORKSPACE, maxBuffer: MAX_OUTPUT });
    return { code: 0, stdout: stdout.slice(0, MAX_OUTPUT), stderr: stderr.slice(0, MAX_OUTPUT) };
  } catch (err) {
    const error = err as { code?: number; stdout?: string; stderr?: string; message?: string };
    return {
      code: typeof error.code === "number" ? error.code : -1,
      stdout: (error.stdout || "").slice(0, MAX_OUTPUT),
      stderr: (error.stderr || error.message || "Unknown error").slice(0, MAX_OUTPUT),
    };
  }
}

async function writeFile(relPath: string, content: string) {
  const target = ensureWorkspacePath(relPath);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, content, "utf8");
  return { path: target, bytes: Buffer.byteLength(content, "utf8") };
}

async function readFile(relPath: string) {
  const target = ensureWorkspacePath(relPath);
  const data = await fs.readFile(target, "utf8");
  const stats = await fs.stat(target);
  return { path: target, size: stats.size, content: data };
}

async function exportPath(relPath: string) {
  const target = ensureWorkspacePath(relPath);
  const stats = await fs.stat(target);

  if (stats.isDirectory()) {
    const zip = new AdmZip();
    const walk = async (current: string, base: string) => {
      const entries = await fs.readdir(current, { withFileTypes: true });
      for (const entry of entries) {
        if (shouldSkip(entry.name)) continue;
        const absPath = path.join(current, entry.name);
        const rel = path.relative(base, absPath);
        if (entry.isDirectory()) {
          await walk(absPath, base);
        } else {
          const data = await fs.readFile(absPath);
          zip.addFile(rel, data);
        }
      }
    };
    await walk(target, target);
    const buffer = zip.toBuffer();
    return { path: relPath, type: "zip", size: buffer.length, data: buffer.toString("base64") };
  }

  const data = await fs.readFile(target);
  return { path: relPath, type: "file", size: stats.size, data: data.toString("base64") };
}

async function buildRepoMap(rootRel = ".", depth = 3, maxEntries = 400) {
  const root = ensureWorkspacePath(rootRel);
  const lines: string[] = [`📁 ${path.basename(root)}/`];
  let entries = 0;

  const walk = async (current: string, currentDepth: number) => {
    if (currentDepth > depth) return;
    const dir = await fs.readdir(current, { withFileTypes: true });
    const dirs = dir.filter((d) => d.isDirectory() && !shouldSkip(d.name)).sort((a, b) => a.name.localeCompare(b.name));
    const files = dir.filter((d) => d.isFile() && !shouldSkip(d.name)).sort((a, b) => a.name.localeCompare(b.name));

    for (const d of dirs) {
      const indent = "  ".repeat(currentDepth);
      lines.push(`${indent}📂 ${d.name}/`);
      entries += 1;
      if (entries >= maxEntries) return;
      await walk(path.join(current, d.name), currentDepth + 1);
      if (entries >= maxEntries) return;
    }

    for (const f of files) {
      const indent = "  ".repeat(currentDepth);
      lines.push(`${indent}📄 ${f.name}`);
      entries += 1;
      if (entries >= maxEntries) return;
    }
  };

  await walk(root, 1);
  return { map: lines.join("\n"), entries };
}

async function searchRepo(query: string, rootRel = ".", context = 2, maxResults = 200, glob?: string | string[]) {
  const root = ensureWorkspacePath(rootRel);
  const globs = Array.isArray(glob) ? glob : glob ? [glob] : [];
  const args = ["rg", query, "--context", String(context), "--max-count", String(maxResults), "--json"];
  for (const g of globs) args.push("-g", g);
  const command = args.join(" ");
  const { code, stdout, stderr } = await runShell(`cd ${root} && ${command}`);
  return { code, stdout, stderr, query, globs, context };
}

function registerSession(res: Response): SessionInfo {
  const id = randomUUID();
  const keepAlive = setInterval(() => {
    res.write(`: keep-alive\n\n`);
  }, 25_000);

  const session: SessionInfo = {
    id,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    messageCount: 0,
    response: res,
    keepAlive,
  };
  sessions.set(id, session);
  return session;
}

function updateSession(session: SessionInfo) {
  session.lastActivity = Date.now();
  session.messageCount += 1;
}

function unregisterSession(id: string) {
  const session = sessions.get(id);
  if (session) {
    clearInterval(session.keepAlive);
    sessions.delete(id);
  }
}

function cleanupStaleSessions() {
  const now = Date.now();
  for (const session of sessions.values()) {
    if (now - session.lastActivity > SESSION_TIMEOUT * 1000) {
      unregisterSession(session.id);
    }
  }
}

app.get(`${BASE_PATH}/sse`, (req, res) => {
  const session = registerSession(res);

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });

  const payload = JSON.stringify({ sessionId: session.id, namespace });
  res.write(`event: connected\ndata: ${payload}\n\n`);

  req.on("close", () => {
    unregisterSession(session.id);
  });
});

app.post(`${BASE_PATH}/messages`, (req, res) => {
  const { sessionId, event = "message", data } = req.body || {};
  const session = sessionId ? sessions.get(sessionId) : undefined;
  if (!session) {
    return res.status(404).json({
      error: "session_expired",
      message: `The MCP session has expired or was disconnected. Please reconnect to ${BASE_PATH}/sse`,
      action: "reconnect",
      reconnect_url: `${BASE_PATH}/sse`,
    });
  }
  updateSession(session);
  session.response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  return res.json({ status: "sent" });
});

app.get(`${BASE_PATH}/tools`, (_req, res) => {
  return res.json({ tools: TOOLS });
});

app.post(`${BASE_PATH}/tool/:name`, async (req, res) => {
  const { name } = req.params;
  try {
    cleanupStaleSessions();
    switch (name) {
      case "help": {
        return res.json({ result: buildEnvInfo() });
      }
      case "sh": {
        const { c, t } = req.body || {};
        if (!c || typeof c !== "string") throw new Error("Missing command (c)");
        const result = await runShell(c, typeof t === "number" ? t : DEFAULT_TIMEOUT);
        return res.json({ result });
      }
      case "write": {
        const { p, c } = req.body || {};
        if (!p || typeof p !== "string" || typeof c !== "string") throw new Error("Missing path (p) or content (c)");
        const result = await writeFile(p, c);
        return res.json({ result });
      }
      case "read": {
        const { p } = req.body || {};
        if (!p || typeof p !== "string") throw new Error("Missing path (p)");
        const result = await readFile(p);
        return res.json({ result });
      }
      case "export": {
        const { p } = req.body || {};
        if (!p || typeof p !== "string") throw new Error("Missing path (p)");
        const result = await exportPath(p);
        return res.json({ result });
      }
      case "repo_map": {
        const { root = ".", depth = 3, max_entries = 400 } = req.body || {};
        const result = await buildRepoMap(root, depth, max_entries);
        return res.json({ result });
      }
      case "search_repo": {
        const { q, root = ".", context = 2, max_results = 200, glob } = req.body || {};
        if (!q || typeof q !== "string") throw new Error("Missing query (q)");
        const result = await searchRepo(q, root, context, max_results, glob);
        return res.json({ result });
      }
      default:
        return res.status(404).json({ error: `Unknown tool: ${name}` });
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return res.status(400).json({ error: message });
  }
});

app.get(`${BASE_PATH}/health`, (_req, res) => {
  res.json({ status: "ok", tools: TOOLS.length, namespace, active_sessions: sessions.size });
});

app.get(`${BASE_PATH}/ping`, (_req, res) => {
  res.json({ status: "pong", namespace });
});

const port = Number(process.env.PORT) || 8000;
app.listen(port, () => {
  console.log(`MCP TypeScript server listening on port ${port} with namespace ${namespace}`);
});
