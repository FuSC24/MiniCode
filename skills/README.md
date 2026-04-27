# MiniCode Skills

Each subdirectory here is one skill. The contract:

```
skills/
  <skill-name>/
    SKILL.md        # required, with frontmatter + body
    references/     # optional, anything else the skill body wants to point at
```

`SKILL.md` frontmatter:

```yaml
---
name: <kebab-case-name>          # how the agent loads the skill
description: <one-line trigger>  # shown in the system prompt skill index
---
```

Everything below `---` is the skill body. The body is what `load_skill` returns
to the model -- treat it as a focused, self-contained instruction sheet.

## Built-in skills

- `code-review` — structured review checklist with output format
- `test-driven-development` — red/green/refactor loop
- `debugging` — systematic root-cause-first workflow
- `writing-plans` — verifiable step plans before implementation

## Adding a skill

1. Create `skills/your-skill/SKILL.md` with frontmatter + body.
2. Restart MiniCode (or run `/skills` in the REPL to reload).
3. The agent will see the skill name + description in its system prompt and
   call `load_skill` when relevant.

## When *not* to write a skill

- One-off task instructions: just say them in chat.
- Project conventions: put in CLAUDE.md instead.
- Personal preferences: save with `save_memory` (cross-session memory).
