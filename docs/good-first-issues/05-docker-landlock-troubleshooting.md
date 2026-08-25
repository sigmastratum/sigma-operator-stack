# Clarify Docker and Landlock troubleshooting

## Files

- `docs/troubleshooting.md`
- `README.md`

## Acceptance

- explain that control-plane availability does not imply executable-profile
  admission;
- preserve the exact `sos capabilities --json` diagnostic path;
- avoid claiming Docker, WSL2, or a kernel broadly compatible from one result.

## Test

```bash
python3 tools/check_public_release.py --repository .
```

## Non-goals

No fallback profile, Docker privilege recommendation, kernel workaround, or
runtime code change.
