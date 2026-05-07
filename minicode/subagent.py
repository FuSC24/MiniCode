"""Spawn a one-shot subagent with a restricted tool set."""
from minicode.config import WORKDIR, MODEL, CONTEXT_TRUNCATE_CHARS, client
from minicode.tools import run_bash, run_read, run_write, run_edit, run_grep


def run_subagent(prompt: str, agent_type: str = "Explore", max_turns: int = 30) -> str:
    """Spawn a one-shot subagent. Default is read-only Explore."""
    sub_tools = [
        {"name": "bash", "description": "Run shell command (read-oriented).",
         "input_schema": {"type": "object",
                          "properties": {"command": {"type": "string"}},
                          "required": ["command"]}},
        {"name": "read_file", "description": "Read file contents.",
         "input_schema": {"type": "object",
                          "properties": {"path": {"type": "string"},
                                         "limit": {"type": "integer"}},
                          "required": ["path"]}},
        {"name": "grep", "description": "Recursive regex grep.",
         "input_schema": {"type": "object",
                          "properties": {"pattern": {"type": "string"},
                                         "path": {"type": "string"},
                                         "glob": {"type": "string"}},
                          "required": ["pattern"]}},
    ]
    if agent_type != "Explore":
        sub_tools += [
            {"name": "write_file", "description": "Write a file.",
             "input_schema": {"type": "object",
                              "properties": {"path": {"type": "string"},
                                             "content": {"type": "string"}},
                              "required": ["path", "content"]}},
            {"name": "edit_file", "description": "Edit an existing file by replacing exact text.",
             "input_schema": {"type": "object",
                              "properties": {"path": {"type": "string"},
                                             "old_text": {"type": "string"},
                                             "new_text": {"type": "string"}},
                              "required": ["path", "old_text", "new_text"]}},
        ]
    handlers = {
        "bash":       lambda **kw: run_bash(kw["command"], kw.get("tool_use_id", "")),
        "read_file":  lambda **kw: run_read(kw["path"], kw.get("tool_use_id", ""), kw.get("limit")),
        "grep":       lambda **kw: run_grep(kw["pattern"], kw.get("path", "."),
                                            kw.get("glob", "*"), kw.get("tool_use_id", "")),
        "write_file": lambda **kw: run_write(kw["path"], kw["content"]),
        "edit_file":  lambda **kw: run_edit(kw["path"], kw["old_text"], kw["new_text"]),
    }
    sys_prompt = (f"You are a subagent ({agent_type}). "
                  f"You operate in a fresh isolated context at {WORKDIR}. "
                  "Return a concise final report; the parent only sees your final text.")
    msgs = [{"role": "user", "content": prompt}]
    resp = None
    for _ in range(max_turns):
        try:
            resp = client.messages.create(model=MODEL, system=sys_prompt,
                                          messages=msgs, tools=sub_tools, max_tokens=8000)
        except Exception as e:
            return f"(subagent failed: {e})"
        msgs.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            break
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                h = handlers.get(b.name, lambda **kw: f"Unknown subtool: {b.name}")
                inp = dict(b.input or {})
                inp["tool_use_id"] = b.id
                try:
                    out = h(**inp)
                except Exception as e:
                    out = f"Error: {e}"
                results.append({"type": "tool_result", "tool_use_id": b.id,
                                "content": str(out)[:CONTEXT_TRUNCATE_CHARS]})
        msgs.append({"role": "user", "content": results})
    if resp:
        return "".join(b.text for b in resp.content if hasattr(b, "text")) or "(no summary)"
    return "(subagent produced no response)"
