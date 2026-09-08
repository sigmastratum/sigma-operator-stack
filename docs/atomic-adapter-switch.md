# Atomic adapter launcher switch

P107-ATOMIC-03 separates package acquisition from repository adapter switching.
The adapter layer never installs, downloads, removes, or resolves a package.
Its caller supplies two already observed `LauncherBinding` values: the retained
predecessor and the explicit successor.

`prepare_atomic_switch` inventories every installed supported adapter and
returns one immutable `sos_atomic_adapter_switch_plan_v1`. Its preview binds:

- the ordered complete client set;
- predecessor and successor package versions, executable digests, and launcher
  binding digests;
- one plan digest, rollback order, and zero package-manager calls.

Preview and missing-TTY paths write nothing. `execute_atomic_switch` revalidates
the complete plan before creating a shared journal under:

```text
.sigma/integrations/atomic-switches/<switch-id>/
```

The append-only hash chain records `prepared`, per-client start/application,
commit, and reverse rollback states. A failure while switching the second
adapter restores both clients to the retained predecessor. A process death
before commit leaves a recoverable journal; `recover_atomic_switch` accepts the
same exact predecessor and successor bindings and deterministically rolls every
planned client back. A committed journal is green only while every client
probes against the successor.

The coordinator never stores executable paths, project content, credentials,
or package bytes. Unknown clients, altered plans, journal gaps, invalid event
order, binding mismatch, target drift, absent TTY, and stale preview fail
closed. Package acquisition, predecessor retention, signature verification,
and release selection remain responsibilities of the successor platform
launcher outside this module.

The integration seam is:

```python
plan = prepare_atomic_switch(
    project,
    predecessor=retained_predecessor_binding,
    successor=verified_successor_binding,
)
preview = plan.preview()
result = execute_atomic_switch(
    plan,
    confirmed=owner_confirmed_preview,
    controlling_tty_observed=True,
)
```

After interruption, use the persisted `switch_id` from the preview/result:

```python
result = recover_atomic_switch(
    project,
    switch_id,
    predecessor=retained_predecessor_binding,
    successor=verified_successor_binding,
)
```
