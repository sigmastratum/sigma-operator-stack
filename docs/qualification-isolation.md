# Qualification Isolation

SOS separates read-only discovery from execution:

- `sos check` observes repository configuration and produces a source-bound
  plan. It never imports or executes project code.
- `sos qualify` is the only execution surface. The caller selects one
  registered family and confirms the run separately.

The first executing family is `python.stdlib-unittest`, with fixed command ID
`python.unittest.v1`. It is intentionally narrow.

## One-run result-integrity lifecycle

One qualification follows this closed sequence:

```text
discovered -> proposed_plan -> admitted_for_one_run
           -> consumed_before_execution -> executed -> result_proposed
```

The proposed plan binds the repository identity, exact application tree and
status, discovery-plan digest, registered family, fixed argv, working
directory, isolation profile and limits. SOS displays that plan before an
interactive confirmation. `--yes` is a command-specific automation
confirmation; it does not broaden the plan or grant reusable authority.

Admission creates a fresh nonce, has a maximum five-minute lifetime and a use
limit of one. SOS persists an exclusive claim before entering the runner. A
crash after that point burns the admission; retry requires a fresh plan and
confirmation. Caller-supplied clocks are not accepted.

The runner writes a closed execution result, followed by a closed
source-bound receipt. Plans, admissions, claims, results and receipts are
immutable. Receipt tips are append-only and ordinal, so concurrent forks,
rollback and replay fail closed. Every normal status, recovery and doctor read
replays the full result chain and its predecessor history. Raw test output,
absolute repository paths and environment values are not serialized.

The four Draft 2020-12 contracts are:

- `sos_qualification_plan_v1`;
- `sos_command_admission_v1`;
- `sos_execution_result_v1`;
- `sos_qualification_receipt_v1`.

They are integrity-pinned in the installed package. These contracts are
qualification evidence only. They cannot accept P101 proposals or grant
commit, push, deploy, release, provider or production authority.

## Linux snapshot profile

`linux-landlock-seccomp-snapshot-v1` is declared only on Linux x86_64. Runtime
admission still fails closed unless Landlock ABI 3 or newer and the seccomp
filter can be installed.

`sos capabilities --json` performs a repository-independent, zero-project-code
probe in fixed-argument child processes. It reports the observed Landlock ABI,
`no_new_privs` admission and seccomp-filter admission separately. The report is
content-safe and digest-bound; it contains no repository path, environment
value, credential or hostname. Unsupported capability exits `2` and cannot
become green. The execution worker repeats the same decision immediately before
project tests and records the exact typed capability failure with internal exit
`78` if the environment changed.

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

## Supported v0.1 boundary

This profile is the complete executable qualification profile supported by the
v0.1 Linux x86_64 vertical. Its support contract is intentionally narrow:

- platform: Linux x86_64 with Landlock ABI 3 or newer and the required seccomp
  support;
- family: Python standard-library `unittest` discovered from tracked project
  files;
- source: an immutable tracked-file snapshot in a disposable execution root;
- canonical repository: inaccessible to project code and re-observed before
  and after execution;
- side effects: no network, child process, namespace or mount authority, a
  closed environment without inherited credentials, and one fixed
  `shell=false` argv;
- resources: declared time, CPU, address-space, descriptor, output, per-file
  write, total writable-byte and writable-entry ceilings;
- integrity: an expiring one-use nonce plus exact source/plan/admission/claim/
  executor/result digests and fail-closed stale, foreign, forged and replayed
  receipt handling.

Cross-server qualification is specific to the exact release artifact. Local
green does not establish broad compatibility; release evidence binds the
candidate, artifact digest and exact observed environment.

Within that boundary, the immutable snapshot and inaccessible canonical
repository are the supported source-isolation design; a literal read-only bind
mount is not required. Total writable quota enforcement is parent-observed
rather than a kernel-mounted per-run quota. Exceeding it kills the worker and
cannot produce green.

This is not a general sandbox. It does not install dependencies, execute
arbitrary commands, support project plugins or claim containment on other
kernels or architectures. Other languages, runner families and kernels are
unsupported until separately implemented and qualified.

Like conventional unit-test runners, the profile does not treat the test
definitions themselves as an attestation authority. A project deliberately
written to falsify its own test result is outside the v0.1 result-integrity
claim and must not be used as trusted evidence. Source binding, immutable
qualification storage and caller/MCP forgery resistance are enforced by the
separate receipt-validation chain. A stronger claim against malicious test
definitions requires a separately trusted runner or independent verifier and
is not part of v0.1.
