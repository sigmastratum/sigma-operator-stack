# Qualification Isolation

SOS separates read-only discovery from execution:

- `sos check` observes repository configuration and produces a source-bound
  plan. It never imports or executes project code.
- `sos qualify` is the only execution surface. The caller selects one
  registered family and confirms the run separately.

The first executing family is `python.stdlib-unittest`, with fixed command ID
`python.unittest.v1`. It is intentionally narrow.

## Linux snapshot profile

`linux-landlock-seccomp-snapshot-v1` is declared only on Linux x86_64. Runtime
admission still fails closed unless Landlock ABI 3 or newer and the seccomp
filter can be installed.

For one run SOS:

1. requires a clean application-source observation;
2. enumerates only Git-tracked files and rejects protected paths, symlinks,
   special files, races and exceeded file/byte limits;
3. copies those bytes into an immutable disposable source projection;
4. creates a separate disposable writable root for the test process;
5. starts one fixed Python worker with `shell=false`, an empty stdin, a closed
   environment and a new process group;
6. uses Landlock to allow read-only access to the source projection and
   bounded read/write access to the writable root while making the canonical
   repository inaccessible;
7. uses seccomp to deny network, child-process, executable, namespace, mount,
   tracing, BPF and key-management syscalls;
8. applies CPU, address-space, open-file, per-file-write, total-writable,
   writable-entry, output and wall-time ceilings;
9. re-observes the canonical source after the run and rejects drift;
10. retains only a digest and typed counts/status, never raw project output.

The profile returns `passed_local` only when at least one discovered test runs,
none is skipped, the unittest result succeeds, the worker exits normally and
all source/resource checks remain valid. `failed`, `skipped`, `not_verified`,
`unsupported`, `blocked` and `stale` are non-green states. Local green is not
a release, CI, deployment or production claim.

## Limits

The current receipt declares the enforced ceilings: 5,000 tracked files,
16 MiB total tracked bytes, 2 MiB per source file, 30 seconds wall time,
20 seconds CPU time, 512 MiB address space, 64 open descriptors, one worker
process, 1 MiB per written file, 16 MiB total writable bytes, 4,096 writable
entries and 1 MiB captured output. The parent kills the complete worker process
group on wall-time or aggregate writable-limit failure.

## Explicit boundary

This is a Linux-specific local qualification profile, not a general sandbox.
It does not install dependencies, execute arbitrary commands, support project
plugins or claim containment on other kernels/architectures. The source input
is an immutable snapshot rather than a canonical-repository bind mount; the
canonical repository is deliberately not visible to project code. Filesystem
quota enforcement is parent-observed rather than a kernel-mounted per-run
quota. These differences remain open before a terminal, platform-general P104
claim.

Like conventional unit-test runners, the profile does not treat the test
definitions themselves as an attestation authority. A project deliberately
written to falsify its own test result is outside this initial result-integrity
claim and must not be used as trusted evidence. Source binding, immutable
qualification storage and caller/MCP forgery resistance remain separate
receipt-validation gates.
