"""MCP (Model Context Protocol) client manager."""

import json
import os
import shlex
import subprocess
import threading
import time

from minicode.config import MCP_DIR, WORKDIR


class MCPClient:
    """Minimal stdio JSON-RPC client for an MCP-like server.

    Speaks: initialize, tools/list, tools/call. Servers that follow that
    handful of methods plug in directly. Everything else (resources, prompts,
    auth flows) is intentionally out of scope here.
    """

    def __init__(self, name: str, command: list, env: dict = None):
        self.name = name
        self.command = command
        self.env = env or {}
        self.proc = None
        self._lock = threading.Lock()
        self._next_id = 1
        self.tools = []  # list of {name, description, input_schema}

    def start(self) -> str:
        try:
            full_env = dict(os.environ)
            full_env.update(self.env)
            self.proc = subprocess.Popen(
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=full_env, cwd=str(WORKDIR),
                text=True, bufsize=1,
            )
        except Exception as e:
            return f"Error starting MCP server '{self.name}': {e}"
        # Initialize handshake.
        init = self._call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "minicode", "version": "0.1"},
        })
        if init is None:
            return f"Error: '{self.name}' did not respond to initialize"
        # List tools.
        listed = self._call("tools/list", {})
        if isinstance(listed, dict):
            for t in listed.get("tools", []):
                self.tools.append({
                    "name": t.get("name"),
                    "description": t.get("description", ""),
                    "input_schema": t.get("inputSchema") or t.get("input_schema") or {"type": "object"},
                })
        return f"MCP server '{self.name}' started with {len(self.tools)} tools"

    def call_tool(self, tool_name: str, arguments: dict) -> str:
        result = self._call("tools/call", {"name": tool_name, "arguments": arguments})
        if isinstance(result, dict):
            content = result.get("content", [])
            if isinstance(content, list):
                texts = []
                for piece in content:
                    if isinstance(piece, dict):
                        if "text" in piece:
                            texts.append(piece["text"])
                        else:
                            texts.append(json.dumps(piece))
                    else:
                        texts.append(str(piece))
                return "\n".join(texts) or json.dumps(result)
            return json.dumps(result)
        return str(result)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                self.proc.kill()

    def _call(self, method: str, params: dict):
        if not self.proc or self.proc.poll() is not None:
            return None
        with self._lock:
            req_id = self._next_id
            self._next_id += 1
            req = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
            try:
                self.proc.stdin.write(json.dumps(req) + "\n")
                self.proc.stdin.flush()
            except Exception as e:
                print(f"  [mcp:{self.name}] write error: {e}")
                return None
            # Naive line-based read, looking for matching id.
            deadline = time.time() + 30
            while time.time() < deadline:
                line = self.proc.stdout.readline()
                # Empty string from readline means EOF -- the server closed
                # its stdout (typically because it exited). Bail out instead
                # of busy-spinning until the deadline.
                if line == "":
                    if self.proc.poll() is not None:
                        print(f"  [mcp:{self.name}] server exited "
                              f"(rc={self.proc.returncode}); aborting call")
                        return None
                    # Pipe quiet but server alive: wait a tick, don't spin.
                    time.sleep(0.05)
                    continue
                try:
                    msg = json.loads(line.strip())
                except Exception:
                    continue
                if msg.get("id") == req_id:
                    if "error" in msg:
                        return {"_error": msg["error"]}
                    return msg.get("result")
            return None


class MCPManager:
    """Loads .minicode/mcp/config.json and routes prefixed tools to the right server."""

    CONFIG_FILE = MCP_DIR / "config.json"

    def __init__(self):
        self.clients = {}
        self._tool_index = {}  # prefixed_name -> (client_name, raw_tool_name, schema)

    def start(self):
        if not self.CONFIG_FILE.exists():
            return
        try:
            cfg = json.loads(self.CONFIG_FILE.read_text())
        except Exception as e:
            print(f"[mcp] config error: {e}")
            return
        for name, spec in cfg.get("servers", {}).items():
            cmd = spec.get("command")
            if not cmd:
                continue
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
            client_obj = MCPClient(name, cmd, env=spec.get("env"))
            msg = client_obj.start()
            print(f"[mcp] {msg}")
            self.clients[name] = client_obj
            for t in client_obj.tools:
                key = f"mcp__{name}__{t['name']}"
                self._tool_index[key] = (name, t["name"], t)

    def stop(self):
        for c in self.clients.values():
            c.stop()

    def tool_specs(self) -> list:
        out = []
        for key, (_, _, t) in self._tool_index.items():
            out.append({
                "name": key,
                "description": f"[mcp] {t.get('description', '')}",
                "input_schema": t.get("input_schema") or {"type": "object"},
            })
        return out

    def list_tools(self) -> str:
        if not self._tool_index:
            return "(no MCP tools loaded)"
        return "\n".join(f"- {k}" for k in sorted(self._tool_index))

    def is_mcp_tool(self, name: str) -> bool:
        return name in self._tool_index

    def call(self, name: str, arguments: dict) -> str:
        if name not in self._tool_index:
            return f"Error: unknown MCP tool '{name}'"
        client_name, raw, _ = self._tool_index[name]
        return self.clients[client_name].call_tool(raw, arguments)


MCP = MCPManager()
