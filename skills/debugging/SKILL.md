---
name: debugging
description: Systematically diagnose bugs, test failures, and unexpected behavior before proposing a fix. Use when facing any failure whose root cause is not obvious.
---

# Systematic Debugging

The fastest debugger is the one who refuses to guess.

## The four-step loop

1. **Reproduce.** Find the smallest input that reliably triggers the failure. If you cannot reproduce, you cannot fix.
2. **Localize.** Bisect the suspect surface: which file, which function, which line. Use `grep`, `git bisect`, prints, or breakpoints — whichever is fastest.
3. **Explain.** Before touching code, state in one sentence *why* the failure happens. If the explanation is "I think maybe...", you are still guessing.
4. **Fix and verify.** Apply the minimum change. Re-run the reproducer. Then run the full test suite to confirm no regression.

## Heuristics

- **Recent change suspect.** Look at `git log -- <file>` for commits touching the buggy area.
- **Off-by-one and boundary.** Empty list, single-element list, exactly-N, N+1.
- **Time / locale / timezone.** Tests that pass at noon and fail at midnight.
- **State pollution.** Order-dependent test failures usually mean a global cleared in the wrong place.
- **Silent except.** A bare `except:` that swallows the real error.

## Anti-patterns

- "Let me try a few things" without forming a hypothesis.
- Adding `try/except` to make the symptom go away.
- Disabling the failing test.
