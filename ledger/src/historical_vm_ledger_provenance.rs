//! Read-only *real Blockstore + frozen Bank* provenance gate for VM receipts.
//!
//! Rooted ledger transaction membership, committed status, Bank fork hash and
//! the post-slot ProgramData account are different identities. Never turn a
//! same-process SVM receipt or an arbitrary Bank snapshot into historical
//! execution certification. This module performs NO writes to the Ledger.
//!
use {
    crate::blockstore::Blockstore,
    serde::Serialize,
    solana_account::{ReadableAccount, state_traits::StateMutWincode as _},
    solana_clock::Slot,
    solana_hash::Hash,
    solana_loader_v3_interface::state::UpgradeableLoaderState,
    solana_pubkey::Pubkey,
    solana_runtime::bank::Bank,
    solana_sdk_ids::bpf_loader_upgradeable,
    solana_sha256_hasher::hash,
    solana_signature::Signature,
    solana_transaction_error::TransactionResult,
};

/// SHA-256 is rendered as lowercase hex to match raw Agave VM receipt
/// contract, not Solana Hash's display/base58 representation.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hash(bytes)
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RootedLedgerBankTransaction {
    pub source: &'static str,
    pub slot: Slot,
    pub parent_slot: Slot,
    pub bank_hash: String,
    pub bank_parent_hash: String,
    pub ledger_blockhash: String,
    pub ledger_previous_blockhash: String,
    pub transaction_index: usize,
    pub outer_instruction_index: usize,
    pub signature: String,
    pub program_id: String,
    pub instruction_data_sha256: String,
    pub transaction_result: String,
    pub rooted_blockstore_and_frozen_bank_match: bool,
    pub independent_source_authentication: bool,
    pub historical_vm_invocation_authenticated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BankProgramDataPostimage {
    pub program_id: String,
    pub programdata_address: String,
    pub loader: String,
    pub deployment_slot: Slot,
    pub bank_slot: Slot,
    pub bank_hash: String,
    pub raw_programdata_elf_sha256: String,
    pub raw_programdata_elf_byte_length: usize,
    pub provenance: &'static str,
    pub proves_execution_time_program_version: bool,
}

/// Reads a *rooted* block's exact ordered transaction and outer instruction.
/// The Bank must be the same frozen fork recorded by this Blockstore. Its
/// hash is not a PoH blockhash, and is never compared to one.
///
/// Even success here is a local Ledger/Bank consistency check, NOT proof
/// that an independently authenticated historical source was used.
#[allow(clippy::too_many_arguments)]
pub fn check_rooted_ledger_bank_transaction(
    blockstore: &Blockstore,
    bank: &Bank,
    slot: Slot,
    transaction_index: usize,
    outer_instruction_index: usize,
    expected_signature: &Signature,
    expected_program: &Pubkey,
    expected_instruction_sha256: &str,
    expected_result: &TransactionResult<()>,
) -> Result<RootedLedgerBankTransaction, String> {
    if bank.slot() != slot || !bank.is_frozen() || !blockstore.is_root(slot) {
        return Err("expected same rooted slot and frozen executing Bank".into());
    }
    let recorded_bank_hash = blockstore
        .get_bank_hash(slot)
        .ok_or("Blockstore missing frozen Bank hash")?;
    if recorded_bank_hash == Hash::default() || bank.hash() != recorded_bank_hash {
        return Err("Blockstore Bank hash mismatches frozen Bank/fork".into());
    }
    let block = blockstore
        .get_rooted_block(slot, true)
        .map_err(|err| format!("Rooted complete Ledger block unavailable: {err}"))?;
    if block.parent_slot != bank.parent_slot() {
        return Err("Ledger parent slot and Bank fork parent disagree".into());
    }
    let entry = block
        .transactions
        .get(transaction_index)
        .ok_or("Ledger transaction index missing")?;
    let signature = entry
        .transaction
        .signatures
        .first()
        .ok_or("Unsigned Ledger transaction cannot bind a VM receipt")?;
    if signature != expected_signature || signature == &Signature::default() {
        return Err("Exact signed Ledger transaction order/identity mismatch".into());
    }
    if &entry.meta.status != expected_result {
        return Err("Committed Ledger transaction status mismatch".into());
    }
    let message = &entry.transaction.message;
    let instruction = message
        .instructions()
        .get(outer_instruction_index)
        .ok_or("Outer instruction index missing")?;
    let program = message
        .static_account_keys()
        .get(usize::from(instruction.program_id_index))
        .ok_or("Invocation Program ID is not a static Ledger account key")?;
    if program != expected_program || sha256_hex(&instruction.data) != expected_instruction_sha256 {
        return Err("Outer instruction Program ID or data hash mismatch".into());
    }
    Ok(RootedLedgerBankTransaction {
        source: "local_rooted_blockstore_frozen_bank_and_exact_order",
        slot,
        parent_slot: block.parent_slot,
        bank_hash: bank.hash().to_string(),
        bank_parent_hash: bank.parent_hash().to_string(),
        ledger_blockhash: block.blockhash,
        ledger_previous_blockhash: block.previous_blockhash,
        transaction_index,
        outer_instruction_index,
        signature: signature.to_string(),
        program_id: program.to_string(),
        instruction_data_sha256: sha256_hex(&instruction.data),
        transaction_result: format!("{:?}", entry.meta.status),
        rooted_blockstore_and_frozen_bank_match: true,
        independent_source_authentication: false,
        historical_vm_invocation_authenticated: false,
    })
}

/// Independently inspect the actual frozen Bank's loader-v3 Program account
/// and ProgramData bytes. Account state can be *later* than an instruction
/// in the SAME slot: this is a post-slot candidate, not an executable
/// identity at an earlier transaction index. The VM loader SHA must still
/// be joined to a separately ordered PreCommit invocation trace.
pub fn inspect_frozen_programdata_postimage(
    bank: &Bank,
    program_id: &Pubkey,
) -> Result<BankProgramDataPostimage, String> {
    if !bank.is_frozen() {
        return Err("ProgramData provenance requires frozen Bank".into());
    }
    let program = bank
        .get_account(program_id)
        .ok_or("Frozen Bank has no Program account")?;
    if !program.executable() || program.owner() != &bpf_loader_upgradeable::id() {
        return Err("Program is not an executable loader-v3 account".into());
    }
    let UpgradeableLoaderState::Program {
        programdata_address,
    } = program
        .state()
        .map_err(|_| "Invalid loader-v3 Program account")?
    else {
        return Err("Wrong Program account state variant".into());
    };
    let data = bank
        .get_account(&programdata_address)
        .ok_or("Frozen Bank has no ProgramData account")?;
    if data.owner() != &bpf_loader_upgradeable::id() {
        return Err("ProgramData owner does not match loader-v3".into());
    }
    let UpgradeableLoaderState::ProgramData { slot, .. } =
        data.state().map_err(|_| "Invalid ProgramData state")?
    else {
        return Err("Wrong ProgramData account state variant".into());
    };
    let original = data
        .data()
        .get(UpgradeableLoaderState::size_of_programdata_metadata()..)
        .ok_or("ProgramData ELF metadata truncated")?;
    if original.len() < 64 || original.get(..4) != Some(b"\x7fELF".as_slice()) || slot > bank.slot()
    {
        return Err("Original deployment ELF/slot invalid".into());
    }
    Ok(BankProgramDataPostimage {
        program_id: program_id.to_string(),
        programdata_address: programdata_address.to_string(),
        loader: bpf_loader_upgradeable::id().to_string(),
        deployment_slot: slot,
        bank_slot: bank.slot(),
        bank_hash: bank.hash().to_string(),
        raw_programdata_elf_sha256: sha256_hex(original),
        raw_programdata_elf_byte_length: original.len(),
        provenance: "frozen_bank_post_slot_ProgramData_not_programcache_at_instruction",
        proves_execution_time_program_version: false,
    })
}
