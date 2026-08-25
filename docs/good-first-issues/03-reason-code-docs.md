# Document one existing reason code

## Files

- `docs/troubleshooting.md`
- the focused test that already emits the reason

## Acceptance

- describe the condition, safe next action, and action users must not take;
- link the explanation to an existing tested reason code;
- keep wording within the current support matrix.

## Test

```bash
python3 tools/check_public_release.py --repository .
```

## Non-goals

No new reason code, fallback, compatibility expansion, or recovery mutation.
