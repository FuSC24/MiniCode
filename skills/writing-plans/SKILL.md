---
name: writing-plans
description: Turn a vague request into a step-by-step plan with verifiable checkpoints. Use before any multi-step implementation, not after.
---

# Writing Plans

A plan is a contract: each step has a check that says "this step is done."

## Format

```
Goal: <one sentence describing what "done" means for the user>

Constraints:
- <hard limits: time, lines, dependencies, surface area>

Steps:
1. <action> -> verify: <check>
2. <action> -> verify: <check>
3. <action> -> verify: <check>

Risks / Open Questions:
- <thing the user must decide before step N>
```

## Rules

- **Verifications must be runnable.** "Tests pass" is fine. "Looks reasonable" is not.
- **One step = one commit.** If a step cannot be committed independently, split it.
- **Surface assumptions.** If step 3 only works when X is true, write that down.
- **Plans are revisable.** When you discover the plan was wrong, update the plan, do not silently drift.

## Use TodoWrite or task_create

- For a short in-session plan, write the steps to `TodoWrite` and update statuses as you go.
- For durable cross-session work, use `task_create` with one task per major step.
