"""
MCP Server - Minimal Shell-First Design

Philosophy: One primary tool (shell), minimal overhead.
ChatGPT should just run commands like it's in a terminal. Keep the link alive by
leaning on the tools instead of ad-hoc text.
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
import secrets
import hashlib
import urllib.parse
from typing import Any, List, Dict, Optional
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager

import httpx
from mcp.server.sse import SseServerTransport
from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
import mcp.types as types

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-ide")

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

# ---------------------------------------------------------------------------
# OAuth Configuration
# ---------------------------------------------------------------------------

# Server base URL (for OAuth endpoints)
SERVER_BASE_URL = os.environ.get(
    "SERVER_BASE_URL",
    "https://vm-tool-81258210604.us-central1.run.app"
)

# Google OAuth (used as identity provider)
GOOGLE_CLIENT_ID = os.environ.get(
    "OAUTH_CLIENT_ID",
    "81258210604-2ie1n8a29a9sgcl0gmpj8agvjn5nja3h.apps.googleusercontent.com"
)
GOOGLE_CLIENT_SECRET = os.environ.get(
    "OAUTH_CLIENT_SECRET",
    "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"
)
GOOGLE_REDIRECT_URI = f"{SERVER_BASE_URL}/oauth/google/callback"
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"

# MCP OAuth Client Registry (clients like ChatGPT register here)
# Format: client_id -> {client_secret, redirect_uris, name}
oauth_clients: Dict[str, Dict[str, Any]] = {}

# Default client for ChatGPT (can be overridden via env vars)
DEFAULT_CLIENT_ID = os.environ.get("MCP_CLIENT_ID", "chatgpt-mcp-client")
DEFAULT_CLIENT_SECRET = os.environ.get("MCP_CLIENT_SECRET", "mcp-client-secret-change-me")

# Register default client
oauth_clients[DEFAULT_CLIENT_ID] = {
    "client_secret": DEFAULT_CLIENT_SECRET,
    "redirect_uris": ["*"],  # Allow any redirect URI for flexibility
    "name": "ChatGPT MCP Client",
}

# OAuth state storage (in production, use Redis or similar)
oauth_states: Dict[str, Dict[str, Any]] = {}
# Authorization codes (short-lived, exchanged for tokens)
authorization_codes: Dict[str, Dict[str, Any]] = {}
# Token storage keyed by access token
oauth_tokens: Dict[str, Dict[str, Any]] = {}

repo_index_cache: dict[str, Any] = {
    "root": None,
    "files": [],
    "built_at": None,
    "total_size": 0,
}

# ---------------------------------------------------------------------------
# Session Management - Track active SSE connections
# ---------------------------------------------------------------------------

# Session tracking for better error messages and reconnection handling
active_sessions: Dict[str, Dict[str, Any]] = {}
SESSION_TIMEOUT = 3600  # 1 hour - sessions older than this are considered stale
KEEP_ALIVE_INTERVAL = 30  # Send keep-alive every 30 seconds


def register_session(session_id: str) -> None:
    """Register a new SSE session."""
    active_sessions[session_id] = {
        "created_at": time.time(),
        "last_activity": time.time(),
        "message_count": 0,
    }
    logger.info("Session registered: %s (total active: %d)", session_id[:8], len(active_sessions))


def update_session_activity(session_id: str) -> bool:
    """Update session activity timestamp. Returns False if session not found."""
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
        logger.info(
            "Session closed: %s (duration: %.1fs, messages: %d)",
            session_id[:8],
            duration,
            session["message_count"],
        )


def cleanup_stale_sessions() -> int:
    """Remove sessions that haven't been active for SESSION_TIMEOUT. Returns count removed."""
    now = time.time()
    stale = [
        sid for sid, info in active_sessions.items()
        if now - info["last_activity"] > SESSION_TIMEOUT
    ]
    for sid in stale:
        logger.warning("Removing stale session: %s", sid[:8])
        active_sessions.pop(sid, None)
    return len(stale)


def get_session_info(session_id: str) -> Optional[Dict[str, Any]]:
    """Get session info if it exists."""
    return active_sessions.get(session_id)


# ---------------------------------------------------------------------------
# OAuth Helper Functions
# ---------------------------------------------------------------------------

def generate_pkce_pair() -> tuple[str, str]:
    """Generate PKCE code verifier and challenge."""
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    return code_verifier, code_challenge


def verify_pkce_challenge(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE code_verifier matches code_challenge."""
    computed = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")
    return secrets.compare_digest(computed, code_challenge)


def validate_oauth_client(client_id: str, client_secret: str = None, redirect_uri: str = None) -> Optional[Dict[str, Any]]:
    """Validate OAuth client credentials."""
    client = oauth_clients.get(client_id)
    if not client:
        return None
    if client_secret and not secrets.compare_digest(client["client_secret"], client_secret):
        return None
    if redirect_uri and client["redirect_uris"] != ["*"]:
        if redirect_uri not in client["redirect_uris"]:
            return None
    return client


def create_google_auth_url(state: str, code_challenge: str) -> str:
    """Create Google OAuth authorization URL (used as identity provider)."""
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
    }
    return f"{GOOGLE_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


async def exchange_google_code(code: str, code_verifier: str) -> Dict[str, Any]:
    """Exchange Google authorization code for access token."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            GOOGLE_TOKEN_ENDPOINT,
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": GOOGLE_REDIRECT_URI,
            },
        )
        if response.status_code != 200:
            raise ValueError(f"Token exchange failed: {response.text}")
        return response.json()


async def get_google_user_info(access_token: str) -> Dict[str, Any]:
    """Get user info from Google."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            GOOGLE_USERINFO_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code != 200:
            raise ValueError(f"Failed to get user info: {response.text}")
        return response.json()


def create_authorization_code(client_id: str, redirect_uri: str, user_info: Dict[str, Any],
                               code_challenge: str = None, code_challenge_method: str = None) -> str:
    """Create an authorization code for the OAuth flow."""
    code = secrets.token_urlsafe(32)
    authorization_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "user_info": user_info,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "created_at": time.time(),
    }
    return code


def create_access_token(user_info: Dict[str, Any], client_id: str) -> tuple[str, int]:
    """Create an access token and return (token, expires_in)."""
    token = secrets.token_urlsafe(32)
    expires_in = 3600  # 1 hour
    oauth_tokens[token] = {
        "user_id": user_info.get("id"),
        "email": user_info.get("email"),
        "name": user_info.get("name"),
        "client_id": client_id,
        "expires_at": time.time() + expires_in,
        "created_at": time.time(),
    }
    return token, expires_in


def validate_token(token: str) -> Optional[Dict[str, Any]]:
    """Validate an access token and return token info if valid."""
    token_info = oauth_tokens.get(token)
    if not token_info:
        return None
    # Check expiration
    if token_info.get("expires_at", 0) < time.time():
        oauth_tokens.pop(token, None)
        return None
    return token_info


def extract_bearer_token(scope: dict) -> Optional[str]:
    """Extract Bearer token from request headers."""
    headers = dict(scope.get("headers", []))
    auth_header = headers.get(b"authorization", b"").decode()
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def cleanup_expired_oauth_states() -> int:
    """Remove expired OAuth states. Returns count removed."""
    now = time.time()
    expired = [
        state for state, info in oauth_states.items()
        if now - info.get("created_at", 0) > 600  # 10 minute expiry
    ]
    for state in expired:
        oauth_states.pop(state, None)
    # Also clean up expired authorization codes
    expired_codes = [
        code for code, info in authorization_codes.items()
        if now - info.get("created_at", 0) > 600  # 10 minute expiry
    ]
    for code in expired_codes:
        authorization_codes.pop(code, None)
    return len(expired) + len(expired_codes)


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

## Repo exploration tools
- repo_map: Summarize repository layout quickly (depth + entry limits)
- read_module: Load a Python module by dotted path (e.g. `app.core.utils`) with syntax highlighting
- index_repo: Build a cached index of files for faster search summaries
- search_repo: Fast ripgrep search with context and glob filters
"""

REPO_TOOLS_INFO = """
# Repo Utilities

## repo_map — "Where am I?"
- Quickly map directory structure. Defaults to the workspace root, depth 3, and 400 entries to avoid noise.

## read_module — "Show me the code"
- Read a Python module using dotted notation (e.g., `pkg.module.submodule`). Falls back to `__init__.py` when given a package.

## index_repo — "Prime the cache"
- Build (or refresh) a lightweight in-memory index of workspace files. Skips common large folders such as `.git` and `node_modules`.

## search_repo — "Targeted search"
- Ripgrep-powered search with context lines and glob filters. Respects the cached index metadata for quick reporting.
"""

ENV_RESOURCE_URI = "vmtool://resources/environment"
REPO_RESOURCE_URI = "vmtool://resources/repo-tools"

# ---------------------------------------------------------------------------
# Repo + Path Helpers
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

    repo_index_cache.update(
        {
            "root": root,
            "files": files,
            "built_at": datetime.utcnow(),
            "total_size": total_size,
        }
    )

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
# Tools - Minimal Set
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
        description="Show environment info, available commands, and usage examples. Call this first to sync context and keep ChatGPT grounded.",
        inputSchema={
            "type": "object",
            "properties": {},
        },
    ),
    types.Tool(
        name="sh",
        description=f"""Run any shell command. Primary tool for everything—use this as your default action hook.

Available: gh (GitHub CLI), git, rg (ripgrep), fd, python, node, gcloud, curl, jq

IMPORTANT: Use 'gh' for GitHub operations, not 'git clone':
{SHELL_EXAMPLES}
If the session feels idle, issue a lightweight command (e.g., `pwd`) to keep the pipe warm.""",
        inputSchema={
            "type": "object",
            "properties": {
                "c": {"type": "string", "description": "Command to run"},
                "t": {"type": "integer", "description": "Timeout seconds (default 300)"},
            },
            "required": ["c"],
        },
    ),
    types.Tool(
        name="write",
        description="Write content to a file. Use after edits to avoid drifting state in the chat window.",
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
        description="Read a file with syntax highlighting. Great for quick context refreshes mid-session.",
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
        description="""Export file(s) as base64 for download. Use this to send files back to the user.

For single file: returns base64 + preview
For directory: creates zip and returns base64""",
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
        description="Summarize repository structure with depth and entry limits to avoid overload. First stop after cloning to orient yourself.",
        inputSchema={
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Root folder relative to workspace"},
                "depth": {"type": "integer", "description": "Folder depth to traverse (default 3)"},
                "max_entries": {"type": "integer", "description": "Maximum entries to include (default 400)"},
            },
        },
    ),
    types.Tool(
        name="read_module",
        description="Read a Python module via dotted path (e.g., package.module). Fast hook when you know the import path.",
        inputSchema={
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Dotted module path"},
                "start": {"type": "integer", "description": "Start line (1-indexed, optional)"},
                "end": {"type": "integer", "description": "End line (inclusive, optional)"},
            },
            "required": ["module"],
        },
    ),
    types.Tool(
        name="index_repo",
        description="Build a cached index of repository files for faster subsequent search and summaries. Run once per repo to keep searches snappy.",
        inputSchema={
            "type": "object",
            "properties": {
                "root": {"type": "string", "description": "Root folder relative to workspace"},
                "max_files": {"type": "integer", "description": "Maximum files to index (default 8000)"},
                "max_file_kb": {"type": "integer", "description": "Skip files larger than this size in KB (default 1024)"},
            },
        },
    ),
    types.Tool(
        name="search_repo",
        description="Ripgrep-powered search with context lines and optional glob filters. Use after index_repo for best speed.",
        inputSchema={
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "Search pattern (passed to ripgrep)"},
                "root": {"type": "string", "description": "Root folder relative to workspace"},
                "context": {"type": "integer", "description": "Context lines (default 2)"},
                "max_results": {"type": "integer", "description": "Max results to return (default 200)"},
                "glob": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Glob filter(s) passed to ripgrep (-g).",
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
    """Expose static resources available from the MCP server."""
    return [
        types.Resource(
            name="environment",
            title="vmtool environment",
            uri=ENV_RESOURCE_URI,
            description="Shell environment details, tools, and usage tips for vmtool.",
            mimeType="text/markdown",
            annotations={"readOnlyHint": True},
        ),
        types.Resource(
            name="repo-tools",
            title="Repository utilities",
            uri=REPO_RESOURCE_URI,
            description="Usage guide for repo_map, read_module, index_repo, and search_repo tools.",
            mimeType="text/markdown",
            annotations={"readOnlyHint": True},
        ),
    ]


@mcp.read_resource()
async def read_resource(uri: str):
    if uri == ENV_RESOURCE_URI:
        return [ReadResourceContents(content=ENV_INFO, mime_type="text/markdown")]
    if uri == REPO_RESOURCE_URI:
        return [ReadResourceContents(content=REPO_TOOLS_INFO, mime_type="text/markdown")]
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
                # Single file export
                data = path.read_bytes()
                b64 = base64.b64encode(data).decode('ascii')
                # Try to get text preview
                preview = None
                try:
                    preview = data.decode('utf-8')[:2000]
                except:
                    pass
                result = md_export(rel_path, len(data), b64, preview)
                return [types.TextContent(type="text", text=result)]
            
            elif path.is_dir():
                # Directory: create zip
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for file_path in path.rglob('*'):
                        if file_path.is_file():
                            # Skip common junk
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
            text = "\n".join(
                [
                    f"## 🗺️ repo_map{truncated}",
                    f"**Root:** `{root.relative_to(WORKSPACE)}`",
                    f"**Depth:** {depth} | **Entries shown:** {min(entries, max_entries)}",
                    "",
                    tree,
                ]
            )
            return [types.TextContent(type="text", text=text)]

        elif name == "read_module":
            module = args.get("module")
            if not module:
                raise ValueError("module is required")

            path = resolve_module_path(module)
            content = path.read_text(errors="replace")
            start = int(args.get("start", 1)) if args.get("start") else 1
            end = int(args.get("end", 0)) if args.get("end") else 0

            if start < 1:
                start = 1
            lines = content.splitlines()
            if end and end >= start:
                snippet = "\n".join(lines[start - 1 : end])
            else:
                snippet = content

            result = md_file(str(path.relative_to(WORKSPACE)), snippet, len(snippet.encode("utf-8")))
            return [types.TextContent(type="text", text=result)]

        elif name == "index_repo":
            root = ensure_workspace_path(args.get("root", "."))
            max_files = int(args.get("max_files", 8000))
            max_kb = int(args.get("max_file_kb", 1024))
            summary = build_repo_index(root, max_files=max_files, max_file_size_kb=max_kb)
            built_at = summary["built_at"].isoformat() + "Z"
            text = "\n".join(
                [
                    "## 🧭 index_repo",
                    f"**Root:** `{root.relative_to(WORKSPACE)}`",
                    f"**Files indexed:** {summary['count']}",
                    f"**Total indexed size:** {summary['total_size']:,} bytes",
                    f"**Built:** {built_at}",
                ]
            )
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

            cmd = [
                "rg",
                "--line-number",
                "--context",
                str(context),
                "--max-count",
                str(max_results),
                query,
            ]

            for pattern in globs:
                cmd.extend(["-g", pattern])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=DEFAULT_TIMEOUT)
            out = stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT]
            err = stderr.decode("utf-8", errors="replace")

            if proc.returncode not in (0, 1):
                raise ValueError(err.strip() or "ripgrep failed")

            index_hint = ""
            if repo_index_cache.get("built_at"):
                built = repo_index_cache["built_at"].isoformat() + "Z"
                index_hint = f"\n**Index:** {len(repo_index_cache['files'])} files | built {built}"

            header = "\n".join(
                [
                    "## 🔎 search_repo",
                    f"**Root:** `{root.relative_to(WORKSPACE)}`",
                    f"**Query:** `{query}`",
                    f"**Context:** {context} | **Max results:** {max_results}",
                    (f"**Globs:** {', '.join(globs)}" if globs else ""),
                ]
            ) + index_hint

            body = out.strip()
            if not body:
                body = "_(no matches)_"

            text = f"{header}\n\n```\n{body}\n```"
            if err.strip():
                text += f"\n\n_Stderr:_\n```\n{err.strip()[:2000]}\n```"

            return [types.TextContent(type="text", text=text)]
        
        else:
            raise ValueError(f"Unknown tool: {name}")
            
    except Exception as e:
        return [types.TextContent(type="text", text=md_error(str(e)))]

# ---------------------------------------------------------------------------
# Server - Minimal ASGI app (no Starlette routing issues)
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
    await send({
        "type": "http.response.body",
        "body": body,
    })


async def send_error_response(send, status: int, error: str, details: str = None) -> None:
    """Send an error response with clear messaging."""
    data = {
        "error": error,
        "status": status,
    }
    if details:
        data["details"] = details
    if status == 404 and "session" in error.lower():
        data["action"] = "reconnect"
        data["hint"] = "The SSE connection has expired. Please establish a new connection to /mcp"
    await send_json_response(send, status, data)


async def send_unauthorized_response(send, error: str = "unauthorized") -> None:
    """Send a 401 Unauthorized response with WWW-Authenticate header."""
    body = json.dumps({
        "error": error,
        "status": 401,
        "auth_url": "/auth/login",
        "hint": "Obtain an access token via OAuth at /auth/login",
    }).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            [b"content-type", b"application/json"],
            [b"www-authenticate", b'Bearer realm="mcp-server"'],
            [b"access-control-allow-origin", b"*"],
        ],
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })


async def send_redirect_response(send, location: str) -> None:
    """Send a redirect response."""
    await send({
        "type": "http.response.start",
        "status": 302,
        "headers": [
            [b"location", location.encode()],
            [b"access-control-allow-origin", b"*"],
        ],
    })
    await send({
        "type": "http.response.body",
        "body": b"",
    })


async def send_html_response(send, status: int, html: str) -> None:
    """Send an HTML response."""
    body = html.encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            [b"content-type", b"text/html; charset=utf-8"],
            [b"access-control-allow-origin", b"*"],
        ],
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })


async def read_request_body(receive) -> bytes:
    """Read the full request body."""
    body = b""
    while True:
        message = await receive()
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body


def parse_form_data(body: bytes) -> Dict[str, str]:
    """Parse application/x-www-form-urlencoded body."""
    params = {}
    if body:
        for pair in body.decode("utf-8").split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[urllib.parse.unquote_plus(key)] = urllib.parse.unquote_plus(value)
    return params


async def app(scope, receive, send):
    """Minimal ASGI app with manual routing, session management, and OAuth."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                logger.info("MCP Shell Server starting (OAuth enabled)")
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                logger.info("MCP Shell Server stopping - cleaning up %d sessions", len(active_sessions))
                active_sessions.clear()
                oauth_states.clear()
                oauth_tokens.clear()
                authorization_codes.clear()
                await send({"type": "lifespan.shutdown.complete"})
                return

    elif scope["type"] == "http":
        path = scope["path"]
        method = scope["method"]
        query_params = parse_query_string(scope.get("query_string", b""))

        # ---------------------------------------------------------------------------
        # OAuth 2.1 Authorization Server Endpoints
        # ---------------------------------------------------------------------------

        # OAuth AS metadata (RFC 8414) - ChatGPT discovers our endpoints here
        if path == "/.well-known/oauth-authorization-server" and method == "GET":
            metadata = {
                "issuer": SERVER_BASE_URL,
                "authorization_endpoint": f"{SERVER_BASE_URL}/authorize",
                "token_endpoint": f"{SERVER_BASE_URL}/token",
                "registration_endpoint": f"{SERVER_BASE_URL}/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
                "scopes_supported": ["openid", "email", "profile", "mcp"],
            }
            await send_json_response(send, 200, metadata)

        # Protected resource metadata - points to our AS
        elif path == "/.well-known/oauth-protected-resource" and method == "GET":
            metadata = {
                "resource": SERVER_BASE_URL,
                "authorization_servers": [SERVER_BASE_URL],
                "scopes_supported": ["openid", "email", "profile", "mcp"],
            }
            await send_json_response(send, 200, metadata)

        # Authorization endpoint - ChatGPT redirects users here
        elif path == "/authorize" and method == "GET":
            cleanup_expired_oauth_states()

            # Get OAuth parameters from ChatGPT
            client_id = query_params.get("client_id", "")
            redirect_uri = urllib.parse.unquote(query_params.get("redirect_uri", ""))
            response_type = query_params.get("response_type", "")
            state = query_params.get("state", "")
            code_challenge = query_params.get("code_challenge", "")
            code_challenge_method = query_params.get("code_challenge_method", "")

            # Validate client
            client = validate_oauth_client(client_id, redirect_uri=redirect_uri)
            if not client:
                await send_error_response(send, 400, "invalid_client", "Unknown client_id or invalid redirect_uri")
                return

            if response_type != "code":
                await send_error_response(send, 400, "unsupported_response_type", "Only 'code' is supported")
                return

            # Generate our own PKCE for Google
            google_verifier, google_challenge = generate_pkce_pair()
            internal_state = secrets.token_urlsafe(32)

            # Store the OAuth flow state (linking ChatGPT's request to Google auth)
            oauth_states[internal_state] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,  # ChatGPT's state
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "google_verifier": google_verifier,
                "created_at": time.time(),
            }

            # Redirect to Google for authentication
            google_auth_url = create_google_auth_url(internal_state, google_challenge)
            logger.info("Authorization request from client %s, redirecting to Google", client_id)
            await send_redirect_response(send, google_auth_url)

        # Google OAuth callback - after user authenticates with Google
        elif path == "/oauth/google/callback" and method == "GET":
            code = query_params.get("code")
            internal_state = query_params.get("state")
            error = query_params.get("error")

            if error:
                logger.warning("Google OAuth error: %s", error)
                await send_html_response(send, 400, f"""
                    <html><body>
                    <h1>Authentication Failed</h1>
                    <p>Google returned an error: {error}</p>
                    </body></html>
                """)
                return

            if not code or not internal_state:
                await send_error_response(send, 400, "invalid_request", "Missing code or state")
                return

            # Retrieve the stored OAuth flow state
            flow_state = oauth_states.pop(internal_state, None)
            if not flow_state:
                await send_error_response(send, 400, "invalid_state", "Session expired, please try again")
                return

            try:
                # Exchange Google code for token
                google_tokens = await exchange_google_code(code, flow_state["google_verifier"])
                google_access_token = google_tokens.get("access_token")

                # Get user info from Google
                user_info = await get_google_user_info(google_access_token)
                logger.info("Google auth successful for: %s", user_info.get("email"))

                # Create our authorization code for ChatGPT
                auth_code = create_authorization_code(
                    client_id=flow_state["client_id"],
                    redirect_uri=flow_state["redirect_uri"],
                    user_info=user_info,
                    code_challenge=flow_state.get("code_challenge"),
                    code_challenge_method=flow_state.get("code_challenge_method"),
                )

                # Redirect back to ChatGPT with authorization code
                redirect_params = {"code": auth_code}
                if flow_state.get("state"):
                    redirect_params["state"] = flow_state["state"]

                redirect_url = f"{flow_state['redirect_uri']}?{urllib.parse.urlencode(redirect_params)}"
                logger.info("Redirecting to client with authorization code")
                await send_redirect_response(send, redirect_url)

            except Exception as e:
                logger.error("Google token exchange failed: %s", str(e))
                await send_html_response(send, 500, f"""
                    <html><body>
                    <h1>Authentication Failed</h1>
                    <p>Error: {str(e)}</p>
                    </body></html>
                """)

        # Token endpoint - ChatGPT exchanges authorization code for access token
        elif path == "/token" and method == "POST":
            body = await read_request_body(receive)
            form_data = parse_form_data(body)

            grant_type = form_data.get("grant_type")
            code = form_data.get("code")
            redirect_uri = form_data.get("redirect_uri")
            client_id = form_data.get("client_id")
            client_secret = form_data.get("client_secret")
            code_verifier = form_data.get("code_verifier")

            # Also check Basic auth header for client credentials
            if not client_id or not client_secret:
                headers = dict(scope.get("headers", []))
                auth_header = headers.get(b"authorization", b"").decode()
                if auth_header.startswith("Basic "):
                    try:
                        decoded = base64.b64decode(auth_header[6:]).decode()
                        client_id, client_secret = decoded.split(":", 1)
                    except Exception:
                        pass

            if grant_type != "authorization_code":
                await send_json_response(send, 400, {"error": "unsupported_grant_type"})
                return

            # Validate client
            client = validate_oauth_client(client_id, client_secret)
            if not client:
                await send_json_response(send, 401, {"error": "invalid_client"})
                return

            # Validate authorization code
            code_info = authorization_codes.pop(code, None)
            if not code_info:
                await send_json_response(send, 400, {"error": "invalid_grant", "error_description": "Invalid or expired code"})
                return

            # Verify code was issued to this client
            if code_info["client_id"] != client_id:
                await send_json_response(send, 400, {"error": "invalid_grant", "error_description": "Code was not issued to this client"})
                return

            # Verify PKCE if code_challenge was provided during authorization
            if code_info.get("code_challenge"):
                if not code_verifier:
                    await send_json_response(send, 400, {"error": "invalid_request", "error_description": "code_verifier required"})
                    return
                if not verify_pkce_challenge(code_verifier, code_info["code_challenge"]):
                    await send_json_response(send, 400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
                    return

            # Create access token
            access_token, expires_in = create_access_token(code_info["user_info"], client_id)
            logger.info("Token issued for user %s to client %s", code_info["user_info"].get("email"), client_id)

            await send_json_response(send, 200, {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in,
            })

        # Dynamic Client Registration (RFC 7591) - ChatGPT registers itself here
        elif path == "/register" and method == "POST":
            body = await read_request_body(receive)
            try:
                client_metadata = json.loads(body.decode("utf-8")) if body else {}
            except json.JSONDecodeError:
                await send_json_response(send, 400, {"error": "invalid_request", "error_description": "Invalid JSON"})
                return

            # Generate a unique client_id and secret for this registration
            new_client_id = f"dyn-{secrets.token_urlsafe(16)}"
            new_client_secret = secrets.token_urlsafe(32)

            # Extract redirect_uris from the request (required by RFC 7591)
            redirect_uris = client_metadata.get("redirect_uris", ["*"])
            client_name = client_metadata.get("client_name", "Dynamic Client")

            # Register the new client
            oauth_clients[new_client_id] = {
                "client_secret": new_client_secret,
                "redirect_uris": redirect_uris if redirect_uris else ["*"],
                "name": client_name,
                "created_at": time.time(),
            }

            logger.info("Dynamic client registered: %s (%s)", new_client_id, client_name)

            # Return the client credentials (RFC 7591 response)
            await send_json_response(send, 201, {
                "client_id": new_client_id,
                "client_secret": new_client_secret,
                "client_id_issued_at": int(time.time()),
                "client_secret_expires_at": 0,  # Never expires
                "redirect_uris": redirect_uris,
                "client_name": client_name,
                "token_endpoint_auth_method": "client_secret_post",
            })

        # Token info endpoint - check token validity
        elif path == "/auth/token" and method == "GET":
            token = extract_bearer_token(scope)
            if not token:
                await send_unauthorized_response(send, "No token provided")
                return

            token_info = validate_token(token)
            if not token_info:
                await send_unauthorized_response(send, "Invalid or expired token")
                return

            await send_json_response(send, 200, {
                "valid": True,
                "email": token_info.get("email"),
                "name": token_info.get("name"),
                "expires_in": int(token_info.get("expires_at", 0) - time.time()),
            })

        # ---------------------------------------------------------------------------
        # MCP Endpoints (OAuth Protected)
        # ---------------------------------------------------------------------------

        # MCP SSE connection endpoint - main entry point for MCP clients
        elif path == "/mcp" and method == "GET":
            # Validate OAuth token
            token = extract_bearer_token(scope)
            if not token:
                logger.warning("MCP connection attempt without token")
                await send_unauthorized_response(send, "Authentication required")
                return

            token_info = validate_token(token)
            if not token_info:
                logger.warning("MCP connection attempt with invalid token")
                await send_unauthorized_response(send, "Invalid or expired token")
                return

            # Generate a session ID for tracking
            session_id = str(uuid.uuid4())
            register_session(session_id)
            # Store user info in session
            active_sessions[session_id]["user"] = token_info.get("email")

            try:
                # Clean up stale sessions periodically
                cleanup_stale_sessions()

                logger.info("MCP connection established for user: %s (session: %s)",
                           token_info.get("email"), session_id[:8])

                async with sse.connect_sse(scope, receive, send) as streams:
                    await mcp.run(streams[0], streams[1], mcp.create_initialization_options())
            except Exception as e:
                logger.error("MCP connection error for session %s: %s", session_id[:8], str(e))
            finally:
                unregister_session(session_id)

        # Message relay endpoint - receives POST messages for SSE streams
        elif path == "/messages" and method == "POST":
            # Validate OAuth token
            token = extract_bearer_token(scope)
            if not token:
                await send_unauthorized_response(send, "Authentication required")
                return

            token_info = validate_token(token)
            if not token_info:
                await send_unauthorized_response(send, "Invalid or expired token")
                return

            try:
                await sse.handle_post_message(scope, receive, send)
            except Exception as e:
                error_msg = str(e)
                logger.warning("Message handling error: %s", error_msg)

                if "not found" in error_msg.lower() or "session" in error_msg.lower():
                    await send_error_response(
                        send,
                        404,
                        "Session not found",
                        "The MCP session has expired or was never established. "
                        "Please reconnect by establishing a new connection to /mcp"
                    )
                else:
                    await send_error_response(
                        send,
                        500,
                        "Message handling failed",
                        error_msg
                    )

        # ---------------------------------------------------------------------------
        # Public Endpoints
        # ---------------------------------------------------------------------------

        # Health check endpoint - enhanced with session info
        elif path == "/health" and method == "GET":
            stale_count = cleanup_stale_sessions()

            health_data = {
                "status": "ok",
                "tools": len(TOOLS),
                "namespace": suggested_namespace,
                "active_sessions": len(active_sessions),
                "stale_sessions_cleaned": stale_count,
                "oauth_enabled": True,
            }
            await send_json_response(send, 200, health_data)

        # Ping endpoint - for keep-alive checks
        elif path == "/ping" and method == "GET":
            await send_json_response(send, 200, {
                "pong": True,
                "timestamp": time.time(),
                "active_sessions": len(active_sessions),
            })

        # Session info endpoint - check if a session is still valid
        elif path == "/session" and method == "GET":
            session_id = query_params.get("id", "")
            if session_id:
                session_info = get_session_info(session_id)
                if session_info:
                    await send_json_response(send, 200, {
                        "valid": True,
                        "session_id": session_id[:8] + "...",
                        "user": session_info.get("user"),
                        "age_seconds": time.time() - session_info["created_at"],
                        "last_activity_seconds_ago": time.time() - session_info["last_activity"],
                        "message_count": session_info["message_count"],
                    })
                else:
                    await send_error_response(
                        send,
                        404,
                        "Session not found",
                        f"Session {session_id[:8]}... does not exist or has expired"
                    )
            else:
                sessions = [
                    {
                        "id": sid[:8] + "...",
                        "user": info.get("user"),
                        "age_seconds": time.time() - info["created_at"],
                        "messages": info["message_count"],
                    }
                    for sid, info in active_sessions.items()
                ]
                await send_json_response(send, 200, {
                    "active_sessions": len(sessions),
                    "sessions": sessions[:10],
                })

        else:
            await send_error_response(
                send,
                404,
                "Endpoint not found",
                f"Path '{path}' does not exist. Available endpoints: "
                "/authorize (GET), /token (POST), /register (POST), /mcp (GET), "
                "/messages (POST), /health (GET), /ping (GET), /session (GET)"
            )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8040)))
