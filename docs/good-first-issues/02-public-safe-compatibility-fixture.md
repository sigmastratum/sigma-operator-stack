# Add a public-safe compatibility fixture

## Files

- `examples/fresh-agent-recovery/`
- `tests/test_public_demo.py`

## Acceptance

- add one synthetic pre-existing project surface;
- freeze its content-safe disposition in the demo checker;
- confirm reset still refuses foreign directories;
- keep provider and network counters at zero.

## Test

```bash
python3 -m unittest -v tests.test_public_demo
```

## Non-goals

No customer-derived shape, real repository path, new detector, or support
claim.
