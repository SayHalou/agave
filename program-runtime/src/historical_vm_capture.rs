//! Opt-in raw original-VM execution evidence for historical verification.
//!
//! The *actual* Agave program loader, SVM thread and VM MemoryMapping are
//! the source; no separate virtual machine or guessed memory regions.
//! This module is compiled out unless historical-vm-capture is selected,
//! and is inactive without AGAVE_HISTORICAL_VM_CAPTURE_DIR.
//!
//! A generated local receipt is NOT proof of an authentic Ledger, verified
//! Bank state, externally trusted collector, or committed transaction.
//! Each independently verified receipt is an execution-time observation.

use {
    serde_json::{Value, json},
    solana_sbpf::{elf::Executable, memory_region::MemoryMapping, vm::ContextObject},
    std::{
        cell::RefCell,
        fs::{self, OpenOptions},
        io::{self, BufWriter, Write},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    },
};

const MAX_SERIALIZED_BYTES: usize = 16 * 1024 * 1024;
const MAX_REGISTER_STEPS: usize = 250_000;
const MAX_HEAP_BYTES: usize = 4 * 1024 * 1024;
static CAPTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct TransactionScope {
    directory: PathBuf,
    slot: u64,
    signature: String,
}

thread_local! {
    static ACTIVE_TRANSACTION: RefCell<Option<TransactionScope>> = const { RefCell::new(None) };
}

/// RAII restores the previous identity across nested tests/reentries.
pub struct TransactionScopeGuard(Option<TransactionScope>);

impl Drop for TransactionScopeGuard {
    fn drop(&mut self) {
        let old = self.0.take();
        ACTIVE_TRANSACTION.with(|current| *current.borrow_mut() = old);
    }
}

/// Bind *this execution thread* to the real SVM transaction signature/slot.
/// Only SVM's execute_loaded_transaction calls this, not untrusted JSON.
pub fn enter_transaction(slot: u64, signature: String) -> TransactionScopeGuard {
    let directory = std::env::var_os("AGAVE_HISTORICAL_VM_CAPTURE_DIR")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from);
    let scope = directory.map(|directory| TransactionScope {
        directory,
        slot,
        signature,
    });
    let old = ACTIVE_TRANSACTION.with(|current| current.replace(scope));
    TransactionScopeGuard(old)
}

fn digest(data: &[u8]) -> String {
    let bytes = solana_sha256_hasher::hash(data).to_bytes();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Maps the original raw ELF SHA-256 (from ProgramCacheEntry::load) separately
/// from the machine text SHA of the actually executing Executable.
fn elf_hash(sha: Option<[u8; 32]>) -> Option<String> {
    sha.map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub struct VmCaptureStart {
    scope: TransactionScope,
    program_id: String,
    deployment_slot: u64,
    loaded_elf_sha256: Option<String>,
    executable_text_sha256: String,
    executable_text_vaddr: u64,
    instruction_index_in_trace: usize,
    instruction_stack_height: usize,
    instruction_data_offset: usize,
    copied_account_data: bool,
    direct_account_pointers_in_program_input: bool,
    r1_initial: u64,
    r2_initial: u64,
    r10_initial: u64,
    regions: Vec<Value>,
    serialized_before: Vec<u8>,
}

/// Capture only evidence already present at the real Agave VM launch. Does
/// not read arbitrary VM host pointers, does not mutate memory or state.
#[allow(clippy::too_many_arguments)]
pub fn begin_vm<C: ContextObject>(
    executable: &Executable<C>,
    mapping: &MemoryMapping,
    program_id: String,
    deployment_slot: u64,
    loaded_elf_sha256: Option<[u8; 32]>,
    instruction_index_in_trace: usize,
    instruction_stack_height: usize,
    instruction_data_offset: usize,
    copied_account_data: bool,
    direct_account_pointers_in_program_input: bool,
    r1: u64,
    r2: u64,
    r10: u64,
    serialized_before: &[u8],
) -> Option<VmCaptureStart> {
    let scope = ACTIVE_TRANSACTION.with(|current| current.borrow().clone())?;
    if serialized_before.len() > MAX_SERIALIZED_BYTES {
        log::warn!("historical VM capture omitted: serialized image over budget");
        return None;
    }
    let (text_vaddr, text) = executable.get_text_bytes();
    let regions = mapping
        .get_regions()
        .iter()
        .map(|region| {
            let range = region.vm_addr_range();
            let label = match range.start >> 32 {
                1 => "program",
                2 => "stack",
                3 => "heap",
                4 => "input",
                _ => "other",
            };
            json!({
                "label":label,
                "virtual_start":range.start,
                "virtual_extent":range.end.saturating_sub(range.start),
                "backing_length":region.len(),
                "readable":true,
                "writable":region.host_buffer().is_mutable(),
                "gap_bytes":region.gap_size(),
            })
        })
        .collect();
    Some(VmCaptureStart {
        scope,
        program_id,
        deployment_slot,
        loaded_elf_sha256: elf_hash(loaded_elf_sha256),
        executable_text_sha256: digest(text),
        executable_text_vaddr: text_vaddr,
        instruction_index_in_trace,
        instruction_stack_height,
        instruction_data_offset,
        copied_account_data,
        direct_account_pointers_in_program_input,
        r1_initial: r1,
        r2_initial: r2,
        r10_initial: r10,
        regions,
        serialized_before: serialized_before.to_vec(),
    })
}

/// Finish evidence before VM stack/heap buffers are returned to the pool.
/// The caller retains the original register trace unchanged for CPI handling.
pub fn finish_vm(
    capture: VmCaptureStart,
    register_trace: &[[u64; 12]],
    serialized_after: &[u8],
    heap_after: &[u8],
    stack_after: &[u8],
    vm_result: &str,
    execution_mode: &str,
    compute_units: u64,
) -> io::Result<PathBuf> {
    if register_trace.len() > MAX_REGISTER_STEPS
        || serialized_after.len() != capture.serialized_before.len()
        || heap_after.len() > MAX_HEAP_BYTES
        || stack_after.len() > 4 * 1024 * 1024
    {
        return Err(io::Error::other(
            "historical VM capture over evidence budget",
        ));
    }
    // The directory is selected explicitly by the operator, not by data
    // inside a transaction. Components cannot traverse out of this root.
    fs::create_dir_all(&capture.scope.directory)?;
    let sequence = CAPTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let capture_dir = capture.scope.directory.join(format!(
        "vm-{}-{}-{}",
        std::process::id(),
        capture.scope.slot,
        sequence
    ));
    fs::create_dir(&capture_dir)?;
    let write_new = |filename: &str, bytes: &[u8]| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(capture_dir.join(filename))?;
        file.write_all(bytes)?;
        file.sync_all()
    };
    write_new("serialized-before.bin", &capture.serialized_before)?;
    write_new("serialized-after.bin", serialized_after)?;
    write_new("heap-after.bin", heap_after)?;
    write_new("stack-after.bin", stack_after)?;
    {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(capture_dir.join("register-trace.jsonl"))?;
        let mut writer = BufWriter::new(file);
        for registers in register_trace {
            serde_json::to_writer(
                &mut writer,
                &json!({
                    "pc": registers[11],
                    "registers": registers,
                }),
            )?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    // Rehash the exact file bytes already flushed by the collector, not
    // a new serialization which could diverge from what was persisted.
    let register_trace_bytes = fs::read(capture_dir.join("register-trace.jsonl"))?;
    if register_trace_bytes.len() > 64 * 1024 * 1024 {
        return Err(io::Error::other(
            "register trace file exceeds evidence budget",
        ));
    }
    // This is a *local execution* metadata receipt. In particular, the slot
    // and signature were taken from SVM's actual executing transaction but
    // have not been externally verified against a Ledger/Bank.
    let receipt = json!({
        "contract": "agave.wp02.historical_vm_execution_candidate.v1",
        "source": "instrumented_agave_program_runtime_not_ledger_attested",
        "phase": "actual_vm_execution_pre_commit",
        "historical_ledger_verified": false,
        "bank_state_verified": false,
        "collector_cryptographically_verified": false,
        "transaction_slot": capture.scope.slot,
        "transaction_signature": capture.scope.signature,
        "program_id": capture.program_id,
        "program_deployment_slot": capture.deployment_slot,
        "loaded_elf_sha256": capture.loaded_elf_sha256,
        "original_machine_text_sha256": capture.executable_text_sha256,
        "original_machine_text_vaddr": capture.executable_text_vaddr,
        "instruction_index_in_trace": capture.instruction_index_in_trace,
        "instruction_stack_height": capture.instruction_stack_height,
        "instruction_data_offset": capture.instruction_data_offset,
        "copied_account_data": capture.copied_account_data,
        "direct_account_pointers_in_program_input":
            capture.direct_account_pointers_in_program_input,
        "r1_initial": capture.r1_initial,
        "r2_initial": capture.r2_initial,
        "r10_initial": capture.r10_initial,
        "vm_regions": capture.regions,
        "serialized_sha256_before": digest(&capture.serialized_before),
        "serialized_sha256_after": digest(serialized_after),
        "heap_sha256_after": digest(heap_after),
        "stack_sha256_after": digest(stack_after),
        "trace_step_count": register_trace.len(),
        "register_trace_sha256": digest(&register_trace_bytes),
        "register_trace_bytes": register_trace_bytes.len(),
        "heap_byte_length": heap_after.len(),
        "stack_byte_length": stack_after.len(),
        "serialized_byte_length": serialized_after.len(),
        "trace_complete": !register_trace.is_empty()
            && execution_mode == "Interpreted",
        "execution_mode": execution_mode,
        "compute_units": compute_units,
        "vm_result": vm_result,
        "current_instruction_root": "unproven",
        "all_path_memory_ssa": "unproven",
        "all_path_pointer_length": "unproven",
        "per_load_bounds": "unknown",
    });
    let encoded = serde_json::to_vec_pretty(&receipt)?;
    write_new("vm-receipt.json", &encoded)?;
    Ok(capture_dir)
}

/// Schema-level negative tests; these do not claim Ledger authority.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_opt_in_never_leaks_a_scope() {
        let old = std::env::var_os("AGAVE_HISTORICAL_VM_CAPTURE_DIR");
        // Do not mutate global environment in a parallel test process.
        if old.is_none() {
            let guard = enter_transaction(7, "synthetic".into());
            ACTIVE_TRANSACTION.with(|scope| assert!(scope.borrow().is_none()));
            drop(guard);
        }
    }

    #[test]
    fn hash_is_exact_bytes_not_a_program_id() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            elf_hash(Some(solana_sha256_hasher::hash(b"abc").to_bytes())),
            Some(digest(b"abc")),
        );
        assert_eq!(elf_hash(None), None);
    }

    #[test]
    fn must_keep_eligibility_unknown_even_with_complete_trace() {
        let status = json!({
            "historical_ledger_verified": false,
            "per_load_bounds": "unknown",
        });
        assert_eq!(status["per_load_bounds"], "unknown");
        assert_ne!(status["historical_ledger_verified"], true);
    }
}
