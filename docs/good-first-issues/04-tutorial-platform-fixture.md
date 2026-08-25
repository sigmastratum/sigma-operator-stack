# Add one tutorial platform fixture

## Files

- `examples/fresh-agent-recovery/expected.json`
- `tests/test_public_demo.py`
- `demo/transcript.md`

## Acceptance

- add one synthetic supported or typed-unsupported capability result;
- maintain expected-state/transcript parity;
- serialize no host, username, path, or environment value.

## Test

```bash
python3 -m unittest -v tests.test_public_demo
```

## Non-goals

No kernel emulation, host probing in CI, provider call, or support-matrix
promotion.
