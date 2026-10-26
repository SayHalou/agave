# WP-02.4 — Agave execution-time SBF VM capture

## Scope and provenance

This feature is in the **existing** `feat/agave-historical-verification-v1`
Agave branch. It extends WP-02's already implemented
`HistoricalExecutionObserver` and Scheduler opt-in PreCommit/PostCommit
calls, not a separate ledger, SVM, execution engine or MemorySSA.

It captures *actual* Agave SBF program-loader execution before an
instruction returns. It has explicit provenance limits:

| Predicate | Evidence |
| --- | --- |
| Real SVM instruction executed | Actual `vm::execute` register trace and VM status |
| Transaction signature and executing slot | `TransactionBatchProcessor::execute_loaded_transaction` scope |
| Program ID and deployment slot | `InvokeContext` and actual `ProgramCacheEntry` |
| Original ELF digest | SHA-256 of bytes passed to `ProgramCacheEntry::load` |
| Executing SBF text digest | SHA-256 of `Executable::get_text_bytes()`; distinct from original ELF identity |
| Actual VM memory regions | `MemoryMapping::get_regions()`, exact `len`, `vm_addr_range`, `gap_size`, backing mutability |
| Exact invocation input | `serialize_parameters` output bytes before and after execution |
| Runtime stack/heap bytes | Captured **before** VM buffers return to the pool |
| Actual original instruction trace | Interpreter `register_trace` before instruction; original 12 registers plus PC |
| Real Ledger/Bank verification | **UNVERIFIED**: SVM test callback alone is not a historical ledger |
| Bank post-commit account image | **UNVERIFIED**: instruction buffers are not committed Bank state |
| Full source ELF version identity after cache swaps | Only available if loaded ELF hash was retained; missing is **Unknown** |
| Global MemorySSA, MustExecute, Pointer/Length, per-Load Bounds | **Unproven / Unknown** unless independently analyzed |

An independently supplied Solana Ledger with slot, fork/Bank state,
transaction ordering, account and ProgramData version is still required.
`PreCommit` evidence must not be mistaken for `PostCommit` or a Bank
postimage; failed, FeesOnly, NoOp and non-executed transactions require
separate classification. A self-consistent JSON receipt or a local
unit-test Bank is **not** a cryptographic attestation of history.

## Enable only in an isolated replay/test environment

The feature is compiled out by default. The operator must explicitly
compile with `historical-vm-capture` (propagated by `solana-svm`
and `solana-syscalls`) **and** set a capture output directory
`AGAVE_HISTORICAL_VM_CAPTURE_DIR` before the program runtime is
constructed. Do not set this for a production validator; it can record
entire instruction inputs and stack/heap bytes including sensitive data.

The runtime uses a thread-local transaction identity scope and a
monotone PID/slot/sequence path under the given directory; no transaction
field is ever used as a filename. Normal compilation, no environment
variable, absent optional feature, or a non-interpreted VM keeps
`trace_complete` absent/false. Diagnostic IO errors are logged but
do **not** change transaction result, which means a missing receipt
must not be interpreted as a successful capture.

Test with the local locked Agave checkout:

```bash
RUSTUP_TOOLCHAIN=1.99.1 cargo test --locked --offline \
  -p solana-program-runtime \
  --features historical-vm-capture \
  --lib historical_vm_capture::tests

RUSTUP_TOOLCHAIN=1.99.1 cargo test --locked --offline \
  -p solana-svm --features historical-vm-capture \
  --test integration_test historical_vm_capture_same_transaction

# Regression of the actual scheduler pre/post commit handler
LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib \
DYLD_FALLBACK_LIBRARY_PATH=/Library/Developer/CommandLineTools/usr/lib \
RUSTUP_TOOLCHAIN=1.99.1 cargo test --locked --offline \
  -p solana-unified-scheduler-pool \
  --lib test_scheduler_historical_observer_opt_in
```

The real SVM integration test spawns a *child process* so its
environment variable never leaks into unrelated parallel tests.
The original executable is the unchanged
`svm/tests/example-programs/hello-solana/hello_solana_program.so`,
loaded through the real ProgramData/ProgramCache. One signed
transaction with zero instruction accounts executes successfully
inside the real Agave program-runtime interpreter:
36 original register-trace instructions and a 48-byte ABI-aligned input.
The test independently checks the original source ELF SHA-256, program
identity, transaction signature, slot, memory regions, all byte-image
SHA-256 values, trace length/initial registers, return status and
all Unproven/Unknown gates.

When an explicit test evidence archive is needed, set
`AGAVE_HISTORICAL_VM_CAPTURE_KEEP_TEST_EVIDENCE=1` for that test
and copy only the resulting dedicated temporary capture directory.
No production Bank/transaction authenticity is inferred from it.

## Original receipt file layout

`vm-<pid>-<slot>-<seq>/` contains:

```text
vm-receipt.json
register-trace.jsonl
serialized-before.bin
serialized-after.bin
heap-after.bin
stack-after.bin
```

The receipt stores the SHA-256 and byte length of the original serialized
input, its postimage, heap, stack, and exact serialized full register
trace. Every VM region includes the actual virtual start/extent,
backing byte length, read/write status and exact gap size; addresses
inside stack gaps are not proven valid. `r1/r2/r10`,
`instruction_data_offset`, direct account mapping mode,
instruction trace index/CPI depth, original ELF hash, executable text
hash, Program ID, deployment slot, transaction signature and slot are
recorded in *one invocation*.

**Important:** For this Agave branch, `instruction_data_offset` is
the actual `r2` value produced by the serializer and can be an
*absolute guest virtual address*, not necessarily an offset relative
to `r1`. Consumers must re-verify its semantics against the actual
runtime feature set, not reinterpret the field name.

`trace_complete=true` means the interpreter emitted a trace for that
specific executed VM invocation. It does **not** establish CFG all-path
coverage or success of an outer transaction. Missing and truncated
register traces are fail-closed for any semantic proof.

## Follow-on proof requirements

A true WP-02 Ledger replay still has to verify authoritative
Blockstore and transaction order, real program deployment snapshot
and Bank provenance. The same-invocation key must be derived from
the real Bank slot, transaction signature, outer instruction index,
CPI trace index and the program's exact original ELF SHA. Compare
the SBF instruction memory writes to the original decoded ELF and
actual memory mappings, and perform the separate committed-state
check after Bank commit. An independent verifier can then certify
only the **concrete executed** Load/Store ranges it observed, while
static path feasibility, all-path alias elimination, and Handler
Pointer/Length/Bounds remain separate obligations.

The SBF Anchor Recognition V2 PR #49 is the consumer of these
lower-level facts; it must not promote a VM sample to Verified merely
because the runtime receipt has internally consistent hashes.
