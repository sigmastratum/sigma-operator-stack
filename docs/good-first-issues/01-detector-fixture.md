# Add one recognized-authority detector fixture

## Files

- `tests/test_existing_stack_compatibility.py`
- `src/sos/compatibility.py` only if the new synthetic fixture exposes a real
  detector gap

## Acceptance

- add one wholly synthetic repository tree for an already documented
  authority family;
- assert the exact `preserve`, `append`, `create`, or `block` disposition;
- prove raw file content and absolute paths are absent from output.

## Test

```bash
PYTHONPATH=src python3 -m unittest -v tests.test_existing_stack_compatibility
```

## Non-goals

No new authority family, policy merge, filesystem scan expansion, or mutation.
