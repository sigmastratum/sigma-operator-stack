# Runtime cache verification

An installed cache is not release authority. Its source must first match the
checked wheel inventory. The verifier then compiles that source with the checked
interpreter, exact filename and optimization level, without executing the source
or importing the installed module.

Marshal bytes are a representation, not a canonical code identity: sharing an
immutable string or frozenset object can change reference records without
changing its value. In particular, two nested functions can contain equal sets
represented either by one shared frozenset or two distinct frozensets. Raw
reserialization equality therefore rejects some equivalent caches.

The isolated verification subprocess compares an explicit recursive structure:

- all argument counts, local count, stack size and flags;
- internal instructions and their public projection, constants (including nested
  code), names and variable names;
- filename, name, qualified name and first line;
- line and exception tables, free variables and cell variables.

Constant types remain distinct. In particular, booleans are not integers and
floating-point/complex components are compared by their exact bits, including
signed zero. Tuples retain order; immutable sets are compared without depending
on iteration order. Unknown constant types, malformed bodies, trailing bytes,
excessive recursion or excessive structural expansion are rejected. Cache magic,
supported interpreter tag and existing inventory, size and process-time limits
remain enforced. Before decoding, a non-allocating structural preflight parses
the pinned CPython 3.11/3.12 marshal wire format. Every string/container length,
reference and nested object must fit the supplied body and bounded node/allocation
budgets. Reference metadata is retained so code-object construction and later
recursive comparison are charged for repeated expansion even when the wire
representation shares one object. The per-code charge conservatively expands all
code fields, covering private instruction copies and recursive constant/string
interning. Malformed, unknown or trailing data is rejected before `marshal.load`.
This avoids platform-dependent address-space limits while bounding allocations
driven by the decoder itself. Deserialization is not execution: no cached code
is evaluated.

For the pinned CPython 3.11/3.12 formats, the comparison includes
`_co_code_adaptive`, not just `co_code`: the latter can deoptimize the exposed
projection and conceal a different internal encoding. Cache verification requires
the same unexecuted internal code state as fresh compilation. A future interpreter
format requires separate qualification, not omission of this check.

## Recovery provenance boundary

Fixing a verifier in a successor does not authorize that successor to recover an
older transaction. A matching product version is insufficient. The ordinary
recovery route continues to require the recorded exact release binding.

If the original recovery controller itself contains the faulty verifier, a
separate, independently reviewed recovery-only compatibility package is needed.
This is a design requirement, not an implemented compatibility switch:

1. Bind the original archive, manifest, wheel, controller and recorded transition
   plan to exact digests; preserve those artifacts unchanged.
2. Separately bind the replacement verification implementation and the
   compatibility controller. Never label the modified controller as the original
   release artifact.
3. Permit only verification and the original journal-driven recovery operation.
   Do not admit install, update, new adapter targets or automatic runtime removal.
4. Before mutation, verify the saved plan, original payload, predecessor and
   successor executables, adapter journal and current files. Refuse provenance
   mismatch or an unrelated pending transaction.
5. Show an explicit recovery preview identifying the verification-policy change
   and the exact old transaction. Require human confirmation and revalidation
   under the existing locks.
6. Use the existing recovery journal to roll back an incomplete switch or verify
   an already committed switch. Never edit bindings to fit the new controller or
   infer rollback from a failed operation.
7. Keep the original install/transition identity and append separately attributable
   compatibility evidence. Preserve other projects, shared runtimes and historical
   generations.

No generic cache bypass, same-version exception, cache deletion workaround or
automatic cross-candidate recovery is authorized by this design. An actual
compatibility package requires exact-artifact tests and independent review before
native recovery is attempted.
