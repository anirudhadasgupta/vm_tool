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
from typing import Any, List
from pathlib import Path

from mcp.server.sse import SseServerTransport
from mcp.server import Server
import mcp.types as types

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-ide")

WORKSPACE = Path("/app/workspace").resolve()
WORKSPACE.mkdir(parents=True, exist_ok=True)

MAX_OUTPUT = 500_000  # 500KB
DEFAULT_TIMEOUT = 300

mcp = Server("shell-mcp")
sse = SseServerTransport("/messages")

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

ENV_INFO = """
# MCP Shell Environment

## ⚠️ EPHEMERAL SESSION
This environment resets between chat sessions. Clone repos fresh each time.

## Workspace
- Location: /app/workspace
- All commands run here by default
- Full read/write access

## Available Tools (use gh for GitHub!)

### GitHub CLI (gh) - PREFERRED for GitHub operations
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
        description="Show environment info, available commands, and usage examples. Call this first to understand what's available.",
        inputSchema={
            "type": "object",
            "properties": {},
        },
    ),
    types.Tool(
        name="sh",
        description=f"""Run any shell command. Primary tool for everything.

Available: gh (GitHub CLI), git, rg (ripgrep), fd, python, node, gcloud, curl, jq

IMPORTANT: Use 'gh' for GitHub operations, not 'git clone':
{SHELL_EXAMPLES}
Call 'help' tool for full documentation.""",
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
]

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
            returncode, stdout, stderr = await shell(cmd, timeout=min(timeout, 1800))
            result = md_command(cmd, returncode, stdout, stderr)
            return [types.TextContent(type="text", text=result)]
        
        elif name == "write":
            path = (WORKSPACE / args["p"]).resolve()
            if not path.is_relative_to(WORKSPACE):
                raise ValueError("Path outside workspace")
            path.parent.mkdir(parents=True, exist_ok=True)
            content = args["c"]
            path.write_text(content)
            return [types.TextContent(type="text", text=f"## ✅ Written\n\n**Path:** `{args['p']}`\n**Size:** {len(content):,} bytes")]
        
        elif name == "read":
            path = (WORKSPACE / args["p"]).resolve()
            if not path.is_relative_to(WORKSPACE):
                raise ValueError("Path outside workspace")
            if not path.exists():
                raise ValueError(f"Not found: {args['p']}")
            content = path.read_text(errors='replace')
            result = md_file(args['p'], content, len(content.encode('utf-8')))
            return [types.TextContent(type="text", text=result)]
        
        elif name == "export":
            rel_path = args["p"]
            path = (WORKSPACE / rel_path).resolve()
            if not path.is_relative_to(WORKSPACE):
                raise ValueError("Path outside workspace")
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
        
        else:
            raise ValueError(f"Unknown tool: {name}")
            
    except Exception as e:
        return [types.TextContent(type="text", text=md_error(str(e)))]

# ---------------------------------------------------------------------------
# Server - Minimal ASGI app (no Starlette routing issues)
# ---------------------------------------------------------------------------

async def app(scope, receive, send):
    """Minimal ASGI app with manual routing."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                logger.info("MCP Shell Server starting")
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                logger.info("MCP Shell Server stopping")
                await send({"type": "lifespan.shutdown.complete"})
                return
    
    elif scope["type"] == "http":
        path = scope["path"]
        method = scope["method"]
        
        if path == "/sse" and method == "GET":
            async with sse.connect_sse(scope, receive, send) as streams:
                await mcp.run(streams[0], streams[1], mcp.create_initialization_options())
        
        elif path == "/messages" and method == "POST":
            await sse.handle_post_message(scope, receive, send)
        
        elif path == "/health" and method == "GET":
            body = b'{"status":"ok","tools":5}'
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
        
        else:
            await send({
                "type": "http.response.start",
                "status": 404,
                "headers": [[b"content-type", b"text/plain"]],
            })
            await send({
                "type": "http.response.body",
                "body": b"Not Found",
            })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
