"""
MCP Server - Minimal Shell-First Design

Philosophy: One primary tool (shell), minimal overhead.
ChatGPT should just run commands like it's in a terminal.
"""

import os
import asyncio
import logging
import base64
import zipfile
import io
import time
import uuid
import json
from typing import Any, List, Dict, Optional
from pathlib import Path
from datetime import datetime

from mcp.server.sse import SseServerTransport
from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
import mcp.types as types

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-server")

DEFAULT_NAMESPACE = "vmtool"


def sanitize_namespace(name: str) -> str:
    """Normalize the namespace used to expose tools to the client."""
    cleaned = name.strip().replace(" ", "-").replace("/", "-")
    return cleaned or DEFAULT_NAMESPACE


WORKSPACE = Path("/app/workspace").resolve()
WORKSPACE.mkdir(parents=True, exist_ok=True)

MAX_OUTPUT = 500_000  # 500KB
DEFAULT_TIMEOUT = 3600
EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", ".mypy_cache", ".pytest_cache"}

repo_index_cache: dict[str, Any] = {
    "root": None,
    "files": [],
    "built_at": None,
    "total_size": 0,
}

# ---------------------------------------------------------------------------
# Session Management - Track active SSE connections
# ---------------------------------------------------------------------------

active_sessions: Dict[str, Dict[str, Any]] = {}
SESSION_TIMEOUT = 3600  # 1 hour


def register_session(session_id: str) -> None:
    """Register a new SSE session."""
    active_sessions[session_id] = {
        "created_at": time.time(),
        "last_activity": time.time(),
        "message_count": 0,
    }
    logger.info("Session registered: %s (total active: %d)", session_id[:8], len(active_sessions))


def update_session_activity(session_id: str) -> bool:
    """Update session activity timestamp."""
    if session_id in active_sessions:
        active_sessions[session_id]["last_activity"] = time.time()
        active_sessions[session_id]["message_count"] += 1
        return True
    return False


def unregister_session(session_id: str) -> None:
    """Unregister an SSE session."""
    if session_id in active_sessions:
        session = active_sessions.pop(session_id)
        duration = time.time() - session["created_at"]
        logger.info("Session closed: %s (duration: %.1fs, messages: %d)",
                    session_id[:8], duration, session["message_count"])


def cleanup_stale_sessions() -> int:
    """Remove sessions that haven't been active for SESSION_TIMEOUT."""
    now = time.time()
    stale = [sid for sid, info in active_sessions.items()
             if now - info["last_activity"] > SESSION_TIMEOUT]
    for sid in stale:
        logger.warning("Removing stale session: %s", sid[:8])
        active_sessions.pop(sid, None)
    return len(stale)


def get_session_info(session_id: str) -> Optional[Dict[str, Any]]:
    """Get session info if it exists."""
    return active_sessions.get(session_id)


# ---------------------------------------------------------------------------
# MCP Server Setup
# ---------------------------------------------------------------------------

suggested_namespace = sanitize_namespace(os.environ.get("VMTOOL_NAMESPACE", DEFAULT_NAMESPACE))
mcp = Server(suggested_namespace)
sse = SseServerTransport("/messages")

logger.info("vmtool namespace: %s", suggested_namespace)

# ---------------------------------------------------------------------------
# Markdown Response Formatters
# ---------------------------------------------------------------------------

def md_command(cmd: str, returncode: int, stdout: str, stderr: str) -> str:
    """Format command result as structured markdown."""
    parts = [f"## `{cmd[:80]}{'...' if len(cmd) > 80 else ''}`\n"]

    status = "✅" if returncode == 0 else "❌"
    parts.append(f"**Status:** {status} (exit {returncode})\n")

    if stdout.strip():
        parts.append("**Output:**")
        parts.append(f"```\n{stdout.strip()[:100000]}\n```\n")

    if stderr.strip():
        label = "**Stderr:**" if stdout.strip() else "**Output:**"
        parts.append(label)
        parts.append(f"```\n{stderr.strip()[:50000]}\n```")

    if not stdout.strip() and not stderr.strip():
        parts.append("_(no output)_")

    return "\n".join(parts)


def md_file(path: str, content: str, size: int) -> str:
    """Format file content as structured markdown."""
    ext = Path(path).suffix.lstrip('.')
    lang = {
        'py': 'python', 'js': 'javascript', 'ts': 'typescript',
        'jsx': 'jsx', 'tsx': 'tsx', 'json': 'json', 'yaml': 'yaml',
        'yml': 'yaml', 'md': 'markdown', 'sh': 'bash', 'bash': 'bash',
        'html': 'html', 'css': 'css', 'sql': 'sql', 'rs': 'rust',
        'go': 'go', 'rb': 'ruby', 'java': 'java', 'cpp': 'cpp',
        'c': 'c', 'h': 'c', 'hpp': 'cpp', 'xml': 'xml', 'toml': 'toml',
    }.get(ext, ext or 'text')

    lines = len(content.splitlines())
    parts = [
        f"## 📄 {path}\n",
        f"**Size:** {size:,} bytes | **Lines:** {lines}\n",
        f"```{lang}",
        content[:200000],
        "```"
    ]
    if size > 200000:
        parts.append("\n_(truncated)_")
    return "\n".join(parts)


def md_error(msg: str) -> str:
    """Format error as markdown."""
    return f"## ❌ Error\n\n{msg}"


def md_export(path: str, size: int, b64: str, preview: str = None) -> str:
    """Format export result with base64 data."""
    parts = [
        f"## 📦 Export: {path}\n",
        f"**Size:** {size:,} bytes\n",
    ]
    if preview:
        parts.append("**Preview:**")
        parts.append(f"```\n{preview[:2000]}\n```\n")
    parts.append("**Base64 Data:**")
    parts.append(f"```\n{b64}\n```")
    return "\n".join(parts)

# ---------------------------------------------------------------------------
# Environment Guide
# ---------------------------------------------------------------------------

def build_env_info(namespace: str) -> str:
    tool_paths = "\n".join(f"- /{namespace}/{tool.name}" for tool in TOOLS)

    return f"""
# MCP Shell Environment

## ⚠️ EPHEMERAL SESSION
This environment resets between chat sessions. Clone repos fresh each time.
If the link feels stale, call the **help** tool again to refresh context.

## Server namespace & tool paths
- Namespace: `{namespace}` (set VMTOOL_NAMESPACE to override)
- Canonical tool paths:
{tool_paths}

## Environment Details
- Timeout: 3600
- OS: Debian
- RAM: 16 GB
- vCPU: 4 core
- CloudSQL (PostGres) attached

## Workspace
- Location: /app/workspace
- All commands run here by default
- Full read/write access

## Available Tools (use gh for GitHub!)

### GitHub CLI (gh) — the GitHub hook
```
gh repo clone owner/repo              # clone repo
gh repo clone owner/repo -- --depth 1 # shallow clone
gh pr list                            # list PRs
gh pr view 123                        # view PR details
gh pr create --title "X" --body "Y"   # create PR
gh pr checkout 123                    # checkout PR branch
gh issue list                         # list issues
gh issue create --title "Bug"         # create issue
gh release list                       # list releases
gh search code "pattern" --repo owner/repo
gh api /repos/owner/repo/contents/path
```

### Code Search (ripgrep - rg)
```
rg "pattern"                  # search all files
rg "pattern" -t py            # python files only
rg "pattern" -t js -t ts      # js and ts files
rg "pattern" -C 3             # with 3 lines context
rg "pattern" -l               # filenames only
rg "pattern" -i               # case insensitive
rg "pattern" -g "!node_modules"  # exclude dir
rg "TODO|FIXME"               # multiple patterns
```

### File Finding (fd)
```
fd "config"                   # find by name
fd -e py                      # by extension
fd -e py -x wc -l             # exec command on results
```

### Git (for local operations)
```
git status
git diff
git log --oneline -20
git branch -a
git checkout -b feature
git add -A && git commit -m "msg"
git push origin feature
```

### Other Tools
- **Python**: python, pip (use --break-system-packages)
- **Node**: node, npm, npx
- **Cloud**: gcloud (pre-authenticated)
- **Data**: jq (JSON), csvkit
- **Utils**: curl, wget, tree, htop, zip/unzip

## Typical Workflow

1. Clone: `gh repo clone facebook/react`
2. Explore: `cd react && tree -L 2`
3. Search: `rg "useState" -t js -l`
4. Read: `cat src/ReactHooks.js`
5. Modify & commit: `git add -A && git commit -m "fix"`
6. PR: `gh pr create --title "Fix" --body "Description"`

## Tips
- Chain commands: `cd repo && rg pattern`
- Use shallow clones for large repos: `gh repo clone owner/repo -- --depth 1`
- ripgrep (rg) is much faster than grep
- fd is much faster than find
"""

# ---------------------------------------------------------------------------
# Path & Repo Helpers
# ---------------------------------------------------------------------------

def ensure_workspace_path(rel_path: str) -> Path:
    path = (WORKSPACE / rel_path).resolve()
    if not path.is_relative_to(WORKSPACE):
        raise ValueError("Path outside workspace")
    return path


def should_skip(name: str) -> bool:
    return name in EXCLUDED_DIRS or name.startswith('.')


def build_repo_map(root: Path, depth: int, max_entries: int) -> tuple[str, int]:
    """Return a text tree map and the number of entries included."""
    lines = [f"📁 {root.name}/"]
    entries = 0

    for current_root, dirnames, filenames in os.walk(root):
        rel_parts = Path(current_root).relative_to(root).parts
        if len(rel_parts) >= depth:
            dirnames[:] = []

        dirnames[:] = [d for d in dirnames if not should_skip(d)]
        filenames = [f for f in filenames if not should_skip(f)]

        dirnames.sort()
        filenames.sort()

        indent = "  " * len(rel_parts)
        for d in dirnames:
            lines.append(f"{indent}📂 {d}/")
            entries += 1
            if entries >= max_entries:
                return "\n".join(lines), entries

        for f in filenames:
            lines.append(f"{indent}📄 {f}")
            entries += 1
            if entries >= max_entries:
                return "\n".join(lines), entries

    return "\n".join(lines), entries


def resolve_module_path(module: str) -> Path:
    dotted = module.replace("\n", "").strip().replace(" ", "")
    if not dotted:
        raise ValueError("Module name cannot be empty")

    candidate = dotted.replace(".", "/")
    direct = WORKSPACE / f"{candidate}.py"
    package_init = WORKSPACE / candidate / "__init__.py"

    for path in (direct, package_init):
        if path.exists():
            if not path.is_relative_to(WORKSPACE):
                break
            return path

    raise ValueError(f"Module not found: {module}")


def build_repo_index(root: Path, max_files: int = 8000, max_file_size_kb: int = 1024):
    files: list[dict[str, Any]] = []
    total_size = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_skip(d)]
        dirnames.sort()

        for filename in sorted(f for f in filenames if not should_skip(f)):
            path = Path(dirpath) / filename
            try:
                size = path.stat().st_size
            except OSError:
                continue

            if size > max_file_size_kb * 1024:
                continue

            relative = path.relative_to(root)
            files.append({"path": str(relative), "size": size})
            total_size += size

            if len(files) >= max_files:
                break

        if len(files) >= max_files:
            break

    repo_index_cache.update({
        "root": root,
        "files": files,
        "built_at": datetime.utcnow(),
        "total_size": total_size,
    })

    return {
        "count": len(files),
        "total_size": total_size,
        "built_at": repo_index_cache["built_at"],
    }

# ---------------------------------------------------------------------------
# Core: Async Shell Execution
# ---------------------------------------------------------------------------

async def shell(cmd: str, timeout: int = DEFAULT_TIMEOUT, cwd: Path = WORKSPACE) -> tuple[int, str, str]:
    """Run shell command, return (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        out = stdout.decode('utf-8', errors='replace')
        err = stderr.decode('utf-8', errors='replace')

        return proc.returncode or 0, out[:MAX_OUTPUT], err[:MAX_OUTPUT]

    except asyncio.TimeoutError:
        return -1, "", f"Timeout after {timeout}s"
    except Exception as e:
        return -1, "", f"Error: {e}"

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

SHELL_EXAMPLES = """
gh repo clone owner/repo           # clone
gh repo clone owner/repo -- --depth 1  # shallow
rg "pattern" -t py                 # search python files
rg "pattern" -l                    # list matching files
fd -e py                           # find python files
cat file.py | head -100            # view file
"""

TOOLS = [
    types.Tool(
        name="help",
        description="Show environment info, available commands, and usage examples. Call this first to sync context.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="sh",
        description=f"""Run any shell command. Primary tool for everything.

Available: gh (GitHub CLI), git, rg (ripgrep), fd, python, node, gcloud, curl, jq

IMPORTANT: Use 'gh' for GitHub operations, not 'git clone':
{SHELL_EXAMPLES}""",
        inputSchema={
            "type": "object",
            "properties": {
                "c": {"type": "string", "description": "Command to run"},
                "t": {"type": "integer", "description": "Timeout seconds (default 3600)"},
            },
            "required": ["c"],
        },
    ),
    types.Tool(
        name="write",
        description="Write content to a file.",
        inputSchema={
            "type": "object",
            "properties": {
                "p": {"type": "string", "description": "File path"},
                "c": {"type": "string", "description": "Content"},
            },
            "required": ["p", "c"],
        },
    ),
    types.Tool(
        name="read",
        description="Read a file with syntax highlighting.",
        inputSchema={
            "type": "object",
            "properties": {
                "p": {"type": "string", "description": "File path"},
            },
            "required": ["p"],
        },
    ),
    types.Tool(
        name="export",
        description="Export file(s) as base64 for download. For directories, creates a zip.",
        inputSchema={
            "type": "object",
            "properties": {
                "p": {"type": "string", "description": "File or directory path"},
            },
            "required": ["p"],
        },
    ),
    types.Tool(
        name="repo_map",
        description="Summarize repository structure with depth and entry limits.",
        inputSchema={
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Root folder relative to workspace"},
                "depth": {"type": "integer", "description": "Folder depth (default 3)"},
                "max_entries": {"type": "integer", "description": "Maximum entries (default 400)"},
            },
        },
    ),
    types.Tool(
        name="search_repo",
        description="Ripgrep-powered search with context lines and glob filters.",
        inputSchema={
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "Search pattern"},
                "root": {"type": "string", "description": "Root folder relative to workspace"},
                "context": {"type": "integer", "description": "Context lines (default 2)"},
                "max_results": {"type": "integer", "description": "Max results (default 200)"},
                "glob": {
                    "anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                    "description": "Glob filter(s) for ripgrep",
                },
            },
            "required": ["q"],
        },
    ),
]

# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

ENV_INFO = build_env_info(suggested_namespace)


@mcp.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(
            name="environment",
            uri="vmtool://resources/environment",
            description="Shell environment details and usage tips.",
            mimeType="text/markdown",
        ),
    ]


@mcp.read_resource()
async def read_resource(uri: str):
    if uri == "vmtool://resources/environment":
        return [ReadResourceContents(content=ENV_INFO, mime_type="text/markdown")]
    raise ValueError(f"Unknown resource: {uri}")

# ---------------------------------------------------------------------------
# Tool Handlers
# ---------------------------------------------------------------------------

@mcp.list_tools()
async def list_tools() -> List[types.Tool]:
    for tool in TOOLS:
        if tool.annotations is None:
            tool.annotations = {}
        tool.annotations["readOnlyHint"] = True
    return TOOLS


@mcp.call_tool()
async def call_tool(name: str, args: Any) -> List[types.TextContent]:
    try:
        if name == "help":
            return [types.TextContent(type="text", text=ENV_INFO)]

        elif name == "sh":
            cmd = args.get("c", "")
            timeout = args.get("t", DEFAULT_TIMEOUT)
            returncode, stdout, stderr = await shell(cmd, timeout=min(timeout, DEFAULT_TIMEOUT))
            result = md_command(cmd, returncode, stdout, stderr)
            return [types.TextContent(type="text", text=result)]

        elif name == "write":
            path = ensure_workspace_path(args["p"])
            path.parent.mkdir(parents=True, exist_ok=True)
            content = args["c"]
            path.write_text(content)
            return [types.TextContent(type="text", text=f"## ✅ Written\n\n**Path:** `{args['p']}`\n**Size:** {len(content):,} bytes")]

        elif name == "read":
            path = ensure_workspace_path(args["p"])
            if not path.exists():
                raise ValueError(f"Not found: {args['p']}")
            content = path.read_text(errors='replace')
            result = md_file(args['p'], content, len(content.encode('utf-8')))
            return [types.TextContent(type="text", text=result)]

        elif name == "export":
            rel_path = args["p"]
            path = ensure_workspace_path(rel_path)
            if not path.exists():
                raise ValueError(f"Not found: {rel_path}")

            if path.is_file():
                data = path.read_bytes()
                b64 = base64.b64encode(data).decode('ascii')
                preview = None
                try:
                    preview = data.decode('utf-8')[:2000]
                except:
                    pass
                result = md_export(rel_path, len(data), b64, preview)
                return [types.TextContent(type="text", text=result)]

            elif path.is_dir():
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for file_path in path.rglob('*'):
                        if file_path.is_file():
                            rel = file_path.relative_to(path)
                            if any(p.startswith('.') for p in rel.parts):
                                continue
                            if 'node_modules' in rel.parts or '__pycache__' in rel.parts:
                                continue
                            try:
                                zf.write(file_path, rel)
                            except:
                                pass

                data = buffer.getvalue()
                b64 = base64.b64encode(data).decode('ascii')
                result = md_export(f"{rel_path}.zip", len(data), b64)
                return [types.TextContent(type="text", text=result)]

        elif name == "repo_map":
            root = ensure_workspace_path(args.get("root", "."))
            depth = max(1, int(args.get("depth", 3)))
            max_entries = max(50, int(args.get("max_entries", 400)))

            tree, entries = build_repo_map(root, depth=depth, max_entries=max_entries)
            truncated = " (truncated)" if entries >= max_entries else ""
            text = "\n".join([
                f"## 🗺️ repo_map{truncated}",
                f"**Root:** `{root.relative_to(WORKSPACE)}`",
                f"**Depth:** {depth} | **Entries shown:** {min(entries, max_entries)}",
                "",
                tree,
            ])
            return [types.TextContent(type="text", text=text)]

        elif name == "search_repo":
            query = args.get("q") or args.get("query")
            if not query:
                raise ValueError("q is required")

            root = ensure_workspace_path(args.get("root", "."))
            context = max(0, int(args.get("context", 2)))
            max_results = max(1, int(args.get("max_results", 200)))
            glob_arg = args.get("glob")
            globs: list[str] = []
            if isinstance(glob_arg, str):
                globs = [glob_arg]
            elif isinstance(glob_arg, list):
                globs = [g for g in glob_arg if isinstance(g, str)]

            cmd = ["rg", "--line-number", "--context", str(context), "--max-count", str(max_results), query]
            for pattern in globs:
                cmd.extend(["-g", pattern])

            proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=DEFAULT_TIMEOUT)
            out = stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT]
            err = stderr.decode("utf-8", errors="replace")

            if proc.returncode not in (0, 1):
                raise ValueError(err.strip() or "ripgrep failed")

            header = "\n".join([
                "## 🔎 search_repo",
                f"**Root:** `{root.relative_to(WORKSPACE)}`",
                f"**Query:** `{query}`",
                f"**Context:** {context} | **Max results:** {max_results}",
                (f"**Globs:** {', '.join(globs)}" if globs else ""),
            ])

            body = out.strip() or "_(no matches)_"
            text = f"{header}\n\n```\n{body}\n```"
            if err.strip():
                text += f"\n\n_Stderr:_\n```\n{err.strip()[:2000]}\n```"

            return [types.TextContent(type="text", text=text)]

        else:
            raise ValueError(f"Unknown tool: {name}")

    except Exception as e:
        return [types.TextContent(type="text", text=md_error(str(e)))]

# ---------------------------------------------------------------------------
# ASGI App - Simple routing
# ---------------------------------------------------------------------------

def parse_query_string(query_string: bytes) -> Dict[str, str]:
    """Parse query string into a dictionary."""
    params = {}
    if query_string:
        for pair in query_string.decode("utf-8").split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key] = value
    return params


async def send_json_response(send, status: int, data: dict) -> None:
    """Send a JSON response."""
    body = json.dumps(data).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            [b"content-type", b"application/json"],
            [b"access-control-allow-origin", b"*"],
        ],
    })
    await send({"type": "http.response.body", "body": body})


async def send_error_response(send, status: int, error: str, details: str = None) -> None:
    """Send an error response."""
    data = {"error": error, "status": status}
    if details:
        data["details"] = details
    if status == 404 and "session" in error.lower():
        data["action"] = "reconnect"
        data["hint"] = "Please establish a new connection to /sse"
    await send_json_response(send, status, data)


async def app(scope, receive, send):
    """Minimal ASGI app - no authentication required."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                logger.info("MCP Server starting")
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                logger.info("MCP Server stopping - %d sessions", len(active_sessions))
                active_sessions.clear()
                await send({"type": "lifespan.shutdown.complete"})
                return

    elif scope["type"] == "http":
        path = scope["path"]
        method = scope["method"]
        query_params = parse_query_string(scope.get("query_string", b""))

        # SSE connection - main MCP endpoint
        if path == "/sse" and method == "GET":
            session_id = str(uuid.uuid4())
            register_session(session_id)

            try:
                cleanup_stale_sessions()
                async with sse.connect_sse(scope, receive, send) as streams:
                    logger.info("MCP connection established: %s", session_id[:8])
                    await mcp.run(streams[0], streams[1], mcp.create_initialization_options())
            except Exception as e:
                logger.error("MCP connection error: %s", str(e))
            finally:
                unregister_session(session_id)

        # Message relay for SSE
        elif path == "/messages" and method == "POST":
            try:
                await sse.handle_post_message(scope, receive, send)
            except Exception as e:
                error_msg = str(e)
                logger.warning("Message error: %s", error_msg)
                if "not found" in error_msg.lower():
                    await send_error_response(send, 404, "Session not found")
                else:
                    await send_error_response(send, 500, "Message handling failed", error_msg)

        # Health check
        elif path == "/health" and method == "GET":
            await send_json_response(send, 200, {
                "status": "ok",
                "tools": len(TOOLS),
                "namespace": suggested_namespace,
                "active_sessions": len(active_sessions),
            })

        # Ping
        elif path == "/ping" and method == "GET":
            await send_json_response(send, 200, {"pong": True, "timestamp": time.time()})

        # Session info
        elif path == "/session" and method == "GET":
            session_id = query_params.get("id", "")
            if session_id:
                info = get_session_info(session_id)
                if info:
                    await send_json_response(send, 200, {
                        "valid": True,
                        "age_seconds": time.time() - info["created_at"],
                        "message_count": info["message_count"],
                    })
                else:
                    await send_error_response(send, 404, "Session not found")
            else:
                await send_json_response(send, 200, {
                    "active_sessions": len(active_sessions),
                })

        else:
            await send_error_response(send, 404, "Not found",
                f"Available: /sse (GET), /messages (POST), /health (GET), /ping (GET)")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8040)))
