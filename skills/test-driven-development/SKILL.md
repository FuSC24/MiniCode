---
name: test-driven-development
description: Drive feature work and bug fixes via failing tests first. Use when implementing any feature or fixing a bug, before writing implementation code.
---

# Test-Driven Development

> Red. Green. Refactor.

The point is not the ceremony, it is the **verifiable success criterion**.
A failing test pins down what "done" means before you write the code.

## Loop

1. **Write the test first.** Use the project's existing test framework.
   The test must fail for the **right reason** -- assertion failure, not import error.
2. **Run it.** Confirm red.
3. **Make it pass with the smallest change possible.** No speculative code.
4. **Run it again.** Confirm green.
5. **Refactor only on green.** If you break the test mid-refactor, revert and retry.

## When the user reports a bug

- First write a test that reproduces the bug. It must fail today.
- Only then look at the fix. The test stays as the regression guard.

## Anti-patterns to avoid

- Writing the implementation first, then a test that "tests" what the code does.
- Mocking the system under test.
- Skipping the red step ("it would obviously fail, so I'll just write the green").

## What good output looks like

```
1. New test `test_auth_rejects_expired_token` -> red (assertion: expected 401, got 200)
2. Patched auth.py:117 to read `iat` field
3. Re-ran test -> green
4. Ran full suite -> 142 passed, 0 failed
```
