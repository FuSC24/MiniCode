---
name: code-review
description: Conduct a structured code review covering correctness, security, and maintainability. Use when the user asks to review a diff, audit a file, or check for bugs.
---

# Code Review

You now have expertise in code review. Work through the checklist in order.
Cite file paths with `path:line` so the user can jump straight to the source.

## Pipeline

1. **Map the change.** Run `git diff` (or `git log -p -1`) and list the touched files. Skim each one.
2. **Correctness.** For every changed function, ask:
   - Does it do what its name + docstring claim?
   - Are edge cases handled (empty input, None, boundaries, concurrency)?
   - Does control flow always reach a defined return?
3. **Security.**
   - Injection: SQL, shell, template, path traversal.
   - Secrets in code or logs.
   - Untrusted input deserialized without validation.
4. **Maintainability.**
   - New abstractions justified by 3+ call sites?
   - Function size, cyclomatic complexity, dead branches.
   - Naming matches existing conventions in the file.
5. **Tests.** Was the change exercised? If not, propose the missing test.

## Output Format

```
## Summary
<1-2 sentence verdict>

## Blocking Issues
- path/file.py:42 — <issue> — <why it blocks>

## Suggestions
- path/file.py:88 — <improvement>

## Nits (optional)
- ...
```

Be specific. "This could be cleaner" without a fix is noise.
