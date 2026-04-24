/// sbf-capture: capture instruction-level account snapshots from ledger replay.
///
/// Produces .sbf_state JSON files (one per matching instruction) compatible
/// with the solana-sbf-ida-processor corpus runner and agave-fuzz-harness.
use {
    base64::{engine::general_purpose::STANDARD as B64, Engine as _},
    crate::ledger_utils::load_and_process_ledger_or_exit,
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
        collections::HashSet,
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

    // Resolve target slot.
    let target_slot = if let Some(sig_str) = arg_matches.value_of("signature") {
        let sig = Signature::from_str(sig_str).expect("invalid --signature");
        blockstore
            .get_transaction_status(sig, &HashSet::default())
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

    let sig_label = arg_matches
        .value_of("signature")
        .map(|s| s[..8].to_string())
        .unwrap_or_else(|| format!("slot{target_slot}"));

    let callback: ProcessInstructionCaptureCallback = Arc::new(
        move |program_id_arg: &Pubkey,
              ix_index: usize,
              tx_context: &TransactionContext,
              is_pre: bool| {
            if program_id_arg != &program_id {
                return;
            }
            if let Some(only) = only_ix_index {
                if ix_index != only {
                    return;
                }
            }
            let snapshot = snapshot_transaction_context(tx_context, program_id_arg, ix_index);
            captures_cb.lock().unwrap().push(CaptureRecord {
                ix_index,
                is_pre,
                snapshot,
                sig_label: sig_label.clone(),
            });
        },
    );

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

    // Write captured snapshots to disk.
    let records = captures.lock().unwrap();
    if records.is_empty() {
        warn!("sbf-capture: no instructions matched program {program_id} in slot {target_slot}");
        return;
    }

    for record in records.iter() {
        let phase = if record.is_pre { "pre" } else { "post" };
        let filename = format!("{}_ix{}_{}.sbf_state", record.sig_label, record.ix_index, phase);
        let path = output_dir.join(&filename);
        let json = serde_json::to_string_pretty(&record.snapshot)
            .expect("failed to serialize sbf_state");
        let mut f = fs::File::create(&path).expect("failed to create output file");
        f.write_all(json.as_bytes()).expect("failed to write output file");
        info!("sbf-capture: wrote {}", path.display());
    }

    println!(
        "sbf-capture: captured {} snapshots → {}",
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
    sig_label: String,
    snapshot: serde_json::Value,
}

/// Serialize the relevant accounts from TransactionContext into a .sbf_state
/// JSON value compatible with sbf_state/schema.py v3.
fn snapshot_transaction_context(
    tx_context: &TransactionContext,
    program_id: &Pubkey,
    ix_index: usize,
) -> serde_json::Value {
    let n = tx_context.get_number_of_accounts();
    let mut accounts = Vec::new();

    for i in 0..n {
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
            "is_signer": false,
            "is_writable": true,
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

    serde_json::json!({
        "version": 3,
        "program_id": program_id.to_string(),
        "program_id_bytes": B64.encode(program_id.as_ref()),
        "program_elf_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "sbf_version": 0,
        "abi_version": 1,
        "transaction": {
            "signature": "capture",
            "slot": 0,
            "instruction_data": "",
            "compute_budget_limit": 200000,
            "compute_units_consumed_before": 0,
            "fidelity": {
                "compute_budget_limit": "exact",
                "compute_units_consumed_before": "exact"
            }
        },
        "accounts": accounts,
        "sysvars": {},
        "cpi_snapshots": [],
        "fidelity": {
            "overall": "exact",
            "accounts": "exact",
            "sysvars": "inferred",
            "cpi": "absent",
            "program_elf": "unknown"
        },
        "engine_compatibility": {
            "debug_replay": true,
            "svm_semantic": true,
            "debug_replay_notes": "",
            "svm_semantic_notes": ""
        },
        "metadata": {
            "capture_source": "ledger_replay",
            "agave_commit": "765ee54adc",
            "instruction_index": ix_index
        }
    })
}
