/// sbf-capture: capture instruction-level account snapshots from ledger replay.
///
/// Produces raw .sbf_capture.json payloads consumed by solana-sbf-ida-processor's
/// Python capture core. The Python side owns .sbf_state/.sbf_result fidelity.
use {
    crate::ledger_utils::load_and_process_ledger_or_exit,
    base64::{engine::general_purpose::STANDARD as B64, Engine as _},
    clap::{App, Arg, ArgMatches, SubCommand},
    log::*,
    solana_accounts_db::accounts_db::AccountsDbConfig,
    solana_ledger::{
        blockstore::Blockstore,
        blockstore_processor::{ProcessInstructionCaptureCallback, ProcessOptions},
        use_snapshot_archives_at_startup::UseSnapshotArchivesAtStartup,
    },
    solana_pubkey::Pubkey,
    solana_runtime::runtime_config::RuntimeConfig,
    solana_signature::Signature,
    solana_transaction_context::TransactionContext,
    std::{
        collections::{BTreeMap, HashSet},
        fs,
        io::Write,
        path::PathBuf,
        str::FromStr,
        sync::{Arc, Mutex},
    },
};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

pub fn sbf_capture_subcommand<'a, 'b>() -> App<'a, 'b> {
    SubCommand::with_name("sbf-capture")
        .about("Capture instruction-level account snapshots via ledger replay")
        .arg(
            Arg::with_name("program_id")
                .long("program-id")
                .value_name("PUBKEY")
                .takes_value(true)
                .required(true)
                .help("Only capture instructions targeting this program"),
        )
        .arg(
            Arg::with_name("signature")
                .long("signature")
                .value_name("BASE58_SIG")
                .takes_value(true)
                .conflicts_with("slot")
                .help("Target transaction signature (looks up slot via blockstore index)"),
        )
        .arg(
            Arg::with_name("slot")
                .long("slot")
                .value_name("N")
                .takes_value(true)
                .help("Target slot (use when transaction status index is unavailable)"),
        )
        .arg(
            Arg::with_name("output_dir")
                .long("output-dir")
                .value_name("PATH")
                .takes_value(true)
                .default_value("./sbf-captures")
                .help("Directory for output .sbf_state files"),
        )
        .arg(
            Arg::with_name("instruction_index")
                .long("instruction-index")
                .value_name("N")
                .takes_value(true)
                .help("Only capture instruction at this index (default: all)"),
        )
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn process_sbf_capture(
    arg_matches: &ArgMatches,
    blockstore: Arc<Blockstore>,
    _ledger_path: &std::path::Path,
    genesis_config: &solana_genesis_config::GenesisConfig,
) {
    let program_id = Pubkey::from_str(
        arg_matches
            .value_of("program_id")
            .expect("--program-id is required"),
    )
    .expect("invalid --program-id pubkey");

    let output_dir = PathBuf::from(arg_matches.value_of("output_dir").unwrap());
    fs::create_dir_all(&output_dir).expect("failed to create output directory");

    let only_ix_index: Option<usize> = arg_matches
        .value_of("instruction_index")
        .map(|s| s.parse().expect("--instruction-index must be a number"));
    let target_signature = arg_matches
        .value_of("signature")
        .map(|sig| Signature::from_str(sig).expect("invalid --signature"));

    // Resolve target slot.
    let target_slot = if let Some(sig) = target_signature.as_ref() {
        blockstore
            .get_transaction_status(sig.clone(), &HashSet::default())
            .expect("blockstore error looking up signature")
            .map(|(slot, _)| slot)
            .unwrap_or_else(|| {
                eprintln!(
                    "Signature not found in blockstore index. \
                     Re-run with --slot <N> to specify the slot directly."
                );
                std::process::exit(1);
            })
    } else if let Some(slot_str) = arg_matches.value_of("slot") {
        slot_str.parse().expect("--slot must be a number")
    } else {
        eprintln!("Either --signature or --slot is required.");
        std::process::exit(1);
    };

    info!("sbf-capture: target slot={target_slot}, program={program_id}");

    // Shared state written by the callback, read after replay.
    let captures: Arc<Mutex<Vec<CaptureRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let captures_cb = Arc::clone(&captures);

    let callback: ProcessInstructionCaptureCallback = Arc::new(move |event| {
        let tx_signature = event.signature;
        let slot = event.slot;
        let program_id_arg = event.program_id;
        let ix_index = event.instruction_index;
        let instruction_data = event.instruction_data;
        let instruction_accounts = event.instruction_account_indices;
        let signer_flags = event.signer_flags;
        let writable_flags = event.writable_flags;
        let tx_context = event.transaction_context;
        let is_pre = event.is_pre;
        if program_id_arg != &program_id {
            return;
        }
        if let Some(expected) = target_signature.as_ref() {
            if tx_signature != Some(expected) {
                return;
            }
        }
        if let Some(only) = only_ix_index {
            if ix_index != only {
                return;
            }
        }
        let signature = tx_signature
            .map(ToString::to_string)
            .unwrap_or_else(|| format!("slot{slot}"));
        let accounts = snapshot_transaction_context(tx_context, signer_flags, writable_flags);
        captures_cb.lock().unwrap().push(CaptureRecord {
            ix_index,
            is_pre,
            signature,
            slot,
            program_id: program_id_arg.to_string(),
            instruction_data: B64.encode(instruction_data),
            instruction_account_indices: instruction_accounts.to_vec(),
            accounts,
        });
    });

    // Build ProcessOptions: halt at target slot, skip PoH verification for speed.
    let process_options = ProcessOptions {
        run_verification: false,
        halt_at_slot: Some(target_slot),
        allow_dead_slots: true,
        runtime_config: RuntimeConfig::default(),
        accounts_db_config: AccountsDbConfig::default(),
        use_snapshot_archives_at_startup: UseSnapshotArchivesAtStartup::Always,
        instruction_capture: Some(callback),
        ..ProcessOptions::default()
    };

    let _output = load_and_process_ledger_or_exit(
        arg_matches,
        genesis_config,
        blockstore,
        process_options,
        None, // transaction_status_sender
    );

    // Write paired capture payloads to disk.  The Python capture core converts
    // this raw boundary format into .sbf_state / .sbf_result and applies the
    // fidelity gates.  Do not emit .sbf_state directly from this Rust side while
    // program ELF/sysvars/compute-unit fields are incomplete.
    let records = captures.lock().unwrap();
    if records.is_empty() {
        warn!("sbf-capture: no instructions matched program {program_id} in slot {target_slot}");
        return;
    }

    let mut pairs: BTreeMap<(String, usize), CapturePair> = BTreeMap::new();
    for record in records.iter() {
        let pair = pairs
            .entry((record.signature.clone(), record.ix_index))
            .or_insert_with(|| CapturePair::from_record(record));
        if record.is_pre {
            pair.pre_accounts = Some(record.accounts.clone());
        } else {
            pair.post_accounts = Some(record.accounts.clone());
        }
    }

    for ((signature, ix_index), pair) in pairs.iter() {
        let short_sig = short_signature(signature);
        let filename = format!(
            "slot{}_{}_ix{}.sbf_capture.json",
            pair.slot, short_sig, ix_index
        );
        let path = output_dir.join(&filename);
        let capture = serde_json::json!({
            "signature": signature,
            "slot": pair.slot,
            "instruction_index": ix_index,
            "invoke_depth": 1,
            "program_id": pair.program_id,
            "instruction_data": pair.instruction_data,
            "pre_accounts": pair.pre_accounts.clone().unwrap_or_default(),
            "post_accounts": pair.post_accounts.clone().unwrap_or_default(),
            "status": if pair.post_accounts.is_some() { "Ok" } else { "unknown" },
            "metadata": {
                "capture_format": "sbf_capture_json_v1",
                "capture_mode": "instrumented_ledger_replay",
                "pre_state_kind": "pre_instruction_exact",
                "agave_commit": "765ee54adc",
                "instruction_account_indices": pair.instruction_account_indices,
            }
        });
        let json = serde_json::to_string_pretty(&capture).expect("failed to serialize sbf capture");
        let mut f = fs::File::create(&path).expect("failed to create output file");
        f.write_all(json.as_bytes())
            .expect("failed to write output file");
        info!("sbf-capture: wrote {}", path.display());
    }

    println!(
        "sbf-capture: captured {} instruction payload(s) from {} snapshot(s) → {}",
        pairs.len(),
        records.len(),
        output_dir.display()
    );
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

struct CaptureRecord {
    ix_index: usize,
    is_pre: bool,
    signature: String,
    slot: u64,
    program_id: String,
    instruction_data: String,
    instruction_account_indices: Vec<u8>,
    accounts: Vec<serde_json::Value>,
}

struct CapturePair {
    slot: u64,
    program_id: String,
    instruction_data: String,
    instruction_account_indices: Vec<u8>,
    pre_accounts: Option<Vec<serde_json::Value>>,
    post_accounts: Option<Vec<serde_json::Value>>,
}

impl CapturePair {
    fn from_record(record: &CaptureRecord) -> Self {
        Self {
            slot: record.slot,
            program_id: record.program_id.clone(),
            instruction_data: record.instruction_data.clone(),
            instruction_account_indices: record.instruction_account_indices.clone(),
            pre_accounts: None,
            post_accounts: None,
        }
    }
}

fn short_signature(signature: &str) -> String {
    signature.chars().take(16).collect()
}

/// Serialize TransactionContext accounts into the raw capture payload consumed
/// by solana-sbf-ida-processor's Python capture core.
fn snapshot_transaction_context(
    tx_context: &TransactionContext,
    signer_flags: &[bool],
    writable_flags: &[bool],
) -> Vec<serde_json::Value> {
    let n = tx_context.get_number_of_accounts();
    let mut accounts = Vec::new();

    for i in 0..n {
        let account_index = usize::from(i);
        let key = match tx_context.get_key_of_account_at_index(i) {
            Ok(k) => *k,
            Err(_) => continue,
        };
        let acct = match tx_context.accounts().try_borrow(i) {
            Ok(a) => a,
            Err(_) => continue,
        };

        use solana_account::ReadableAccount;
        let pubkey_bytes = B64.encode(key.as_ref());
        let owner_bytes = B64.encode(acct.owner().as_ref());
        let data_b64 = B64.encode(acct.data());

        accounts.push(serde_json::json!({
            "pubkey": key.to_string(),
            "pubkey_bytes": pubkey_bytes,
            "index": i,
            "is_signer": signer_flags.get(account_index).copied().unwrap_or(false),
            "is_writable": writable_flags.get(account_index).copied().unwrap_or(false),
            "lamports": acct.lamports(),
            "data": data_b64,
            "owner": acct.owner().to_string(),
            "owner_bytes": owner_bytes,
            "executable": acct.executable(),
            "rent_epoch": acct.rent_epoch(),
            "fidelity": {
                "lamports": "exact",
                "data": "exact"
            }
        }));
    }

    accounts
}
