"""Token estimation + history compaction."""
import json
import time

from minicode.config import (
    KEEP_RECENT_RESULTS, PRESERVE_RESULT_TOOLS,
    TRANSCRIPT_DIR, WORKDIR, client, MODEL,
)


def estimate_tokens(messages: list) -> int:
    """Cheap token approximation. Good enough to trigger compaction."""
    return len(json.dumps(messages, default=str)) // 4


def microcompact(messages: list):
    """Replace older tool_result payloads with placeholders, in place."""
    tool_results = []
    for msg in messages:
        if msg["role"] == "user" and isinstance(msg.get("content"), list):
            for part in msg["content"]:
                if isinstance(part, dict) and part.get("type") == "tool_result":
                    tool_results.append(part)
    if len(tool_results) <= KEEP_RECENT_RESULTS:
        return
    tool_name_map = {}
    for msg in messages:
        if msg["role"] == "assistant":
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if hasattr(block, "type") and block.type == "tool_use":
                        tool_name_map[block.id] = block.name
    for part in tool_results[:-KEEP_RECENT_RESULTS]:
        if not isinstance(part.get("content"), str) or len(part["content"]) <= 100:
            continue
        tool_id = part.get("tool_use_id", "")
        tool_name = tool_name_map.get(tool_id, "unknown")
        if tool_name in PRESERVE_RESULT_TOOLS:
            continue
        part["content"] = f"[Previous: used {tool_name}]"


def auto_compact(messages: list, focus: str = None) -> list:
    """Persist a transcript, summarize, return a fresh seed conversation."""
    TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    path = TRANSCRIPT_DIR / f"transcript_{int(time.time())}.jsonl"
    with open(path, "w") as f:
        for msg in messages:
            f.write(json.dumps(msg, default=str) + "\n")
    conv = json.dumps(messages, default=str)[:80000]
    prompt = (
        "Summarize this conversation for continuity. Structure your summary:\n"
        "1) Task overview: core request, success criteria, constraints\n"
        "2) Current state: completed work, files touched, artifacts created\n"
        "3) Key decisions and discoveries: constraints, errors, failed approaches\n"
        "4) Next steps: remaining actions, blockers, priority order\n"
        "5) Context to preserve: user preferences, domain details, commitments\n"
        "Be concise but preserve critical details.\n"
    )
    if focus:
        prompt += f"\nPay special attention to: {focus}\n"
    try:
        resp = client.messages.create(model=MODEL, max_tokens=4000,
                                      messages=[{"role": "user", "content": prompt + "\n" + conv}])
        summary = resp.content[0].text
    except Exception as e:
        summary = f"(compact failed: {e}; raw transcript at {path.relative_to(WORKDIR)})"
    cont = (
        "This session is being continued from a previous conversation that ran out "
        "of context. The summary below covers the earlier portion of the conversation.\n\n"
        f"{summary}\n\n"
        "Please continue from where we left off without asking the user further questions."
    )
    return [{"role": "user", "content": cont}]
