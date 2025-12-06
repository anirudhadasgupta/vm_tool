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
from datetime import datetime

from mcp.server.sse import SseServerTransport
from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
import mcp.types as types

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-ide")

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

mcp = Server("vmtool")
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

## Repo exploration tools
- repo_map: Summarize repository layout quickly (depth + entry limits)
- read_module: Load a Python module by dotted path (e.g. `app.core.utils`) with syntax highlighting
- index_repo: Build a cached index of files for faster search summaries
- search_repo: Fast ripgrep search with context and glob filters
"""

REPO_TOOLS_INFO = """
# Repo Utilities

## repo_map
- Quickly map directory structure. Defaults to the workspace root, depth 3, and 400 entries to avoid noise.

## read_module
- Read a Python module using dotted notation (e.g., `pkg.module.submodule`). Falls back to `__init__.py` when given a package.

## index_repo
- Build (or refresh) a lightweight in-memory index of workspace files. Skips common large folders such as `.git` and `node_modules`.

## search_repo
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
# Resources
# ---------------------------------------------------------------------------


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
    types.Tool(
        name="repo_map",
        description="Summarize repository structure with depth and entry limits to avoid overload.",
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
        description="Read a Python module via dotted path (e.g., package.module). Falls back to __init__.py for packages.",
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
        description="Build a cached index of repository files for faster subsequent search and summaries.",
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
        description="Ripgrep-powered search with context lines and optional glob filters.",
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
            body = b'{"status":"ok","tools":9}'
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
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8040)))
