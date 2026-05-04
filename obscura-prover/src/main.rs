//! tonkl-prover: CLI driver for the Tonkl Protocol in-process witness solver.
//!
//! Subcommands:
//!   witness  - Solve witness and write witness.gz (original behavior)
//!   prove    - Full pipeline: solve witness, generate proof via bb, clean up
//!   compute  - Compute note commitments, nullifiers, pk from JSON (wallet helper)
//!
//! All pure functions live in the library crate (lib.rs).

use clap::{Parser, Subcommand};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use zeroize::Zeroize;

use obscura_prover::{
    build_merkle_tree, derive_note_sk_hex, note_commitment, note_nullifier,
    poseidon2_hash_2, serialize_witness_stack_msgpack, solve_witness, str_to_field,
    wallet_derive_pk, FieldElement, NoteFields,
};

const EXPECTED_CIRCUIT_HASH: &str = env!("OBSCURA_CIRCUIT_HASH");

/// Tonkl Protocol -- in-process witness solver and prover.
#[derive(Parser, Debug)]
#[command(name = "tonkl-prover", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // Legacy flat args for backward compatibility (no subcommand = witness mode)
    /// Path to compiled Noir circuit JSON artifact.
    #[arg(short, long, global = true)]
    circuit: Option<PathBuf>,

    /// Output path (witness.gz for `witness`, proof directory for `prove`).
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Solve the witness and write witness.gz (original behavior).
    Witness {
        /// Path to compiled Noir circuit JSON artifact.
        #[arg(short, long)]
        circuit: Option<PathBuf>,

        /// Output file path for the solved witness (gzipped).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Full pipeline: solve witness, generate proof via bb, verify, clean up.
    /// The witness file is created temporarily and secure-deleted after proving.
    Prove {
        /// Path to compiled Noir circuit JSON artifact.
        #[arg(short, long)]
        circuit: Option<PathBuf>,

        /// Output directory for proof files (proof, public_inputs).
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Path to bb binary. Defaults to ~/.bb/bb.
        #[arg(long)]
        bb: Option<PathBuf>,

        /// Path to verification key. If not provided, generates one.
        #[arg(short = 'k', long)]
        vk: Option<PathBuf>,

        /// Skip standalone verification after proving.
        #[arg(long)]
        skip_verify: bool,
    },

    /// Compute note commitments, nullifiers, or public keys from JSON stdin.
    /// Used by the wallet to compute hashes without needing nargo/hasher.
    ///
    /// Input JSON format (via stdin):
    ///   {"op": "commitment", "value": "100", "asset_id": "1",
    ///    "owner_pk_x": "0x...", "owner_pk_y": "0x...", "rho": "1001"}
    ///   {"op": "nullifier", "cm": "0x...", "owner_sk": "0x..."}
    ///   {"op": "derive_pk", "sk": "0x..."}
    ///   {"op": "full_note", "value": "100", "asset_id": "1", "sk": "0x...", "rho": "1001"}
    ///
    /// Output: JSON object with computed values to stdout.
    Compute,
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct SensitiveInput {
    raw: String,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Witness { circuit, output }) => {
            let circuit = circuit.as_ref().or(cli.circuit.as_ref()).unwrap_or_else(|| {
                eprintln!("[tonkl-prover] --circuit is required");
                process::exit(1);
            });
            let output = output.as_ref().or(cli.output.as_ref()).unwrap_or_else(|| {
                eprintln!("[tonkl-prover] --output is required");
                process::exit(1);
            });
            cmd_witness(circuit, output);
        }
        Some(Commands::Prove {
            circuit,
            output,
            bb,
            vk,
            skip_verify,
        }) => {
            let circuit = circuit.as_ref().or(cli.circuit.as_ref()).unwrap_or_else(|| {
                eprintln!("[tonkl-prover] --circuit is required");
                process::exit(1);
            });
            let output = output.as_ref().or(cli.output.as_ref()).unwrap_or_else(|| {
                eprintln!("[tonkl-prover] --output is required");
                process::exit(1);
            });
            let bb_path = bb.clone().unwrap_or_else(default_bb_path);
            cmd_prove(circuit, output, &bb_path, vk.as_deref(), *skip_verify);
        }
        Some(Commands::Compute) => {
            cmd_compute();
        }
        None => {
            // Legacy mode: no subcommand = witness (backward compatible)
            let circuit = cli.circuit.as_ref().unwrap_or_else(|| {
                eprintln!("[tonkl-prover] --circuit is required");
                process::exit(1);
            });
            let output = cli.output.as_ref().unwrap_or_else(|| {
                eprintln!("[tonkl-prover] --output is required");
                process::exit(1);
            });
            cmd_witness(circuit, output);
        }
    }
}

// -- Subcommand: witness ------------------------------------------------------

fn cmd_witness(circuit_path: &Path, output_path: &Path) {
    let (input, circuit_json) = read_stdin_and_circuit(circuit_path);
    let inputs_json = maybe_apply_hd_derivation(&input.raw);

    let solved = solve_witness(&circuit_json, &inputs_json).unwrap_or_else(|e| {
        eprintln!("[tonkl-prover] {e}");
        process::exit(1);
    });
    drop(input);

    let gz_buf = serialize_and_gzip(&solved.entries);
    write_file(output_path, &gz_buf);

    eprintln!(
        "[tonkl-prover] Written: {} ({} bytes)",
        output_path.display(),
        gz_buf.len()
    );
    eprintln!("[tonkl-prover] sk was never on disk. Done.");
}

// -- Subcommand: prove --------------------------------------------------------

fn cmd_prove(
    circuit_path: &Path,
    output_dir: &Path,
    bb_path: &Path,
    vk_path: Option<&Path>,
    skip_verify: bool,
) {
    // Verify bb exists
    if !bb_path.is_file() {
        eprintln!(
            "[tonkl-prover] bb not found at {}\n  \
             Install: curl -L https://raw.githubusercontent.com/AztecProtocol/\
             aztec-packages/master/barretenberg/cpp/installation/install | bash",
            bb_path.display()
        );
        process::exit(1);
    }

    let (input, circuit_json) = read_stdin_and_circuit(circuit_path);
    let inputs_json = maybe_apply_hd_derivation(&input.raw);

    // 1. Solve witness
    eprintln!("[tonkl-prover] Solving witness...");
    let solved = solve_witness(&circuit_json, &inputs_json).unwrap_or_else(|e| {
        eprintln!("[tonkl-prover] {e}");
        process::exit(1);
    });
    drop(input);

    // 2. Write temporary witness.gz
    let gz_buf = serialize_and_gzip(&solved.entries);
    let witness_tmp = output_dir.join(".witness_tmp.gz");
    fs::create_dir_all(output_dir).ok();
    write_file(&witness_tmp, &gz_buf);
    drop(gz_buf);
    eprintln!(
        "[tonkl-prover] Temp witness: {} ({} entries)",
        witness_tmp.display(),
        solved.entries.len()
    );

    // 3. Generate VK if needed
    let vk_dir;
    let vk_file: PathBuf;
    if let Some(existing_vk) = vk_path {
        vk_file = existing_vk.to_path_buf();
        eprintln!("[tonkl-prover] Using existing VK: {}", vk_file.display());
    } else {
        vk_dir = output_dir.join("vk");
        fs::create_dir_all(&vk_dir).ok();
        eprintln!("[tonkl-prover] Generating verification key...");
        let status = Command::new(bb_path)
            .args([
                "write_vk",
                "-b", &circuit_path.to_string_lossy(),
                "-o", &vk_dir.to_string_lossy(),
            ])
            .status()
            .unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] Failed to run bb write_vk: {e}");
                secure_delete(&witness_tmp);
                process::exit(1);
            });
        if !status.success() {
            eprintln!("[tonkl-prover] bb write_vk failed (exit {})", status);
            secure_delete(&witness_tmp);
            process::exit(1);
        }
        vk_file = vk_dir.join("vk");
        eprintln!("[tonkl-prover] VK written: {}", vk_file.display());
    }

    // 4. Prove (+ inline verify)
    eprintln!("[tonkl-prover] Generating proof...");
    let proof_dir = output_dir.join("proof");
    fs::create_dir_all(&proof_dir).ok();

    let mut prove_args = vec![
        "prove".to_string(),
        "-b".to_string(), circuit_path.to_string_lossy().to_string(),
        "-w".to_string(), witness_tmp.to_string_lossy().to_string(),
        "-o".to_string(), proof_dir.to_string_lossy().to_string(),
        "-k".to_string(), vk_file.to_string_lossy().to_string(),
    ];
    if !skip_verify {
        prove_args.push("--verify".to_string());
    }

    let status = Command::new(bb_path)
        .args(&prove_args)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("[tonkl-prover] Failed to run bb prove: {e}");
            secure_delete(&witness_tmp);
            process::exit(1);
        });

    // 5. Secure-delete witness IMMEDIATELY after bb consumes it
    secure_delete(&witness_tmp);

    if !status.success() {
        eprintln!("[tonkl-prover] bb prove failed (exit {})", status);
        process::exit(1);
    }

    let proof_file = proof_dir.join("proof");
    let pub_inputs_file = proof_dir.join("public_inputs");
    eprintln!("[tonkl-prover] Proof saved: {}", proof_file.display());
    eprintln!(
        "[tonkl-prover] Public inputs: {}",
        pub_inputs_file.display()
    );

    // 6. Standalone verify (unless --skip-verify)
    if !skip_verify {
        eprintln!("[tonkl-prover] Verifying proof...");
        let status = Command::new(bb_path)
            .args([
                "verify",
                "-k", &vk_file.to_string_lossy(),
                "-p", &proof_file.to_string_lossy(),
                "-i", &pub_inputs_file.to_string_lossy(),
            ])
            .status()
            .unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] Failed to run bb verify: {e}");
                process::exit(1);
            });
        if !status.success() {
            eprintln!("[tonkl-prover] bb verify FAILED (exit {})", status);
            process::exit(1);
        }
        eprintln!("[tonkl-prover] Proof verified successfully.");
    }

    eprintln!();
    eprintln!("[tonkl-prover] All steps passed.");
    eprintln!("  proof         : {}", proof_file.display());
    eprintln!("  public_inputs : {}", pub_inputs_file.display());
    eprintln!("  vk            : {}", vk_file.display());
    eprintln!("  witness       : DELETED (sk was never on disk)");
}

// -- Subcommand: compute -------------------------------------------------------

fn cmd_compute() {
    let mut input = SensitiveInput { raw: String::new() };
    io::stdin()
        .read_to_string(&mut input.raw)
        .unwrap_or_else(|e| {
            eprintln!("[tonkl-prover] Failed to read stdin: {e}");
            process::exit(1);
        });

    let json: serde_json::Value = serde_json::from_str(&input.raw).unwrap_or_else(|e| {
        eprintln!("[tonkl-prover] Invalid JSON: {e}");
        process::exit(1);
    });

    let op = json["op"].as_str().unwrap_or_else(|| {
        eprintln!("[tonkl-prover] Missing 'op' field. Use: commitment, nullifier, derive_pk, full_note");
        process::exit(1);
    });

    let result: serde_json::Value = match op {
        "commitment" => {
            let note = parse_note_fields(&json);
            let cm = note_commitment(&note).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] commitment failed: {e}");
                process::exit(1);
            });
            serde_json::json!({
                "commitment": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&cm)))
            })
        }
        "nullifier" => {
            let cm = parse_field(&json, "cm");
            let sk = parse_field(&json, "owner_sk");
            let nf = note_nullifier(cm, sk).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] nullifier failed: {e}");
                process::exit(1);
            });
            serde_json::json!({
                "nullifier": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&nf)))
            })
        }
        "derive_pk" => {
            let sk = parse_field(&json, "sk");
            let (pk_x, pk_y) = wallet_derive_pk(sk).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] derive_pk failed: {e}");
                process::exit(1);
            });
            serde_json::json!({
                "pk_x": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&pk_x))),
                "pk_y": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&pk_y)))
            })
        }
        "full_note" => {
            // Derive pk from sk, then compute commitment and nullifier.
            // One-shot: the wallet sends (value, asset_id, sk, rho) and gets
            // back (pk_x, pk_y, commitment, nullifier) -- everything needed
            // to track a note.
            let sk = parse_field(&json, "sk");
            let value = parse_field(&json, "value");
            let asset_id = parse_field(&json, "asset_id");
            let rho = parse_field(&json, "rho");

            let (pk_x, pk_y) = wallet_derive_pk(sk).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] derive_pk failed: {e}");
                process::exit(1);
            });

            let note = NoteFields {
                value,
                asset_id,
                owner_pk_x: pk_x,
                owner_pk_y: pk_y,
                rho,
            };
            let cm = note_commitment(&note).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] commitment failed: {e}");
                process::exit(1);
            });
            let nf = note_nullifier(cm, sk).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] nullifier failed: {e}");
                process::exit(1);
            });

            serde_json::json!({
                "pk_x": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&pk_x))),
                "pk_y": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&pk_y))),
                "commitment": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&cm))),
                "nullifier": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&nf)))
            })
        }
        "hash_2" => {
            let a = parse_field(&json, "a");
            let b = parse_field(&json, "b");
            let h = poseidon2_hash_2(a, b).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] hash_2 failed: {e}");
                process::exit(1);
            });
            serde_json::json!({
                "hash": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&h)))
            })
        }
        "merkle_tree" => {
            let leaves_arr = json["leaves"].as_array().unwrap_or_else(|| {
                eprintln!("[tonkl-prover] merkle_tree: 'leaves' must be an array");
                process::exit(1);
            });
            let leaves: Vec<FieldElement> = leaves_arr
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let s = v.as_str().unwrap_or_else(|| {
                        eprintln!("[tonkl-prover] merkle_tree: leaf[{i}] must be a string");
                        process::exit(1);
                    });
                    str_to_field(s, &format!("leaf[{i}]")).unwrap_or_else(|e| {
                        eprintln!("[tonkl-prover] {e}");
                        process::exit(1);
                    })
                })
                .collect();

            let result = build_merkle_tree(&leaves).unwrap_or_else(|e| {
                eprintln!("[tonkl-prover] merkle_tree: {e}");
                process::exit(1);
            });

            let paths_json: Vec<serde_json::Value> = result
                .paths
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "index_bits": p.index_bits.to_vec(),
                        "siblings": p.siblings.iter().map(|s| {
                            format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(s)))
                        }).collect::<Vec<String>>()
                    })
                })
                .collect();

            serde_json::json!({
                "root": format!("0x{}", hex::encode(obscura_prover::fe_to_be_32(&result.root))),
                "paths": paths_json,
                "leaf_count": leaves.len()
            })
        }
        other => {
            eprintln!(
                "[tonkl-prover] Unknown op '{other}'. Use: commitment, nullifier, derive_pk, full_note, hash_2, merkle_tree"
            );
            process::exit(1);
        }
    };

    drop(input);
    println!("{}", serde_json::to_string(&result).unwrap());
}

fn parse_field(json: &serde_json::Value, name: &str) -> FieldElement {
    let s = json[name].as_str().or_else(|| json[name].as_u64().map(|_| "")).unwrap_or_else(|| {
        eprintln!("[tonkl-prover] compute: missing field '{name}'");
        process::exit(1);
    });
    // Handle numeric JSON values
    if s.is_empty() {
        let n = json[name].as_u64().unwrap();
        return FieldElement::from(n as u128);
    }
    str_to_field(s, name).unwrap_or_else(|e| {
        eprintln!("[tonkl-prover] compute: {e}");
        process::exit(1);
    })
}

fn parse_note_fields(json: &serde_json::Value) -> NoteFields {
    NoteFields {
        value: parse_field(json, "value"),
        asset_id: parse_field(json, "asset_id"),
        owner_pk_x: parse_field(json, "owner_pk_x"),
        owner_pk_y: parse_field(json, "owner_pk_y"),
        rho: parse_field(json, "rho"),
    }
}

// -- Shared helpers -----------------------------------------------------------

fn read_stdin_and_circuit(circuit_path: &Path) -> (SensitiveInput, String) {
    let mut input = SensitiveInput { raw: String::new() };
    io::stdin()
        .read_to_string(&mut input.raw)
        .unwrap_or_else(|e| {
            eprintln!("[tonkl-prover] Failed to read stdin: {e}");
            process::exit(1);
        });

    if input.raw.trim().is_empty() {
        eprintln!("[tonkl-prover] Empty stdin. Pipe JSON circuit inputs.");
        process::exit(1);
    }

    let circuit_json = fs::read_to_string(circuit_path).unwrap_or_else(|e| {
        eprintln!(
            "[tonkl-prover] Cannot read {}: {e}",
            circuit_path.display()
        );
        process::exit(1);
    });

    verify_circuit_hash(circuit_json.as_bytes());

    (input, circuit_json)
}

fn serialize_and_gzip(entries: &[(u32, [u8; 32])]) -> Vec<u8> {
    let mut framed = serialize_witness_stack_msgpack(entries);

    {
        let n = framed.len().min(16);
        let hex: String = framed[..n]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("[tonkl-prover] msgpack header (first {n} bytes): {hex}");
        eprintln!(
            "[tonkl-prover] msgpack payload: {} bytes pre-gzip",
            framed.len()
        );
    }

    let mut gz_buf = Vec::new();
    {
        let mut encoder = GzEncoder::new(&mut gz_buf, Compression::default());
        encoder.write_all(&framed).unwrap_or_else(|e| {
            eprintln!("[tonkl-prover] Gzip failed: {e}");
            process::exit(1);
        });
        encoder.finish().unwrap_or_else(|e| {
            eprintln!("[tonkl-prover] Gzip finalize failed: {e}");
            process::exit(1);
        });
    }

    framed.zeroize();
    gz_buf
}

fn write_file(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(path, data).unwrap_or_else(|e| {
        eprintln!(
            "[tonkl-prover] Cannot write {}: {e}",
            path.display()
        );
        process::exit(1);
    });
}

/// Overwrite a file with random bytes, then delete it.
/// Best-effort defense-in-depth; SSD wear-levelling limits effectiveness.
fn secure_delete(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Ok(metadata) = fs::metadata(path) {
        let len = metadata.len() as usize;
        if len > 0 {
            // Pass 1: zeros
            let zeros = vec![0u8; len];
            let _ = fs::write(path, &zeros);
            // Pass 2: ones
            let ones = vec![0xFFu8; len];
            let _ = fs::write(path, &ones);
            // Pass 3: random (use simple PRNG -- this is defense-in-depth, not crypto)
            let mut rng_buf = vec![0u8; len];
            for (i, byte) in rng_buf.iter_mut().enumerate() {
                *byte = (i.wrapping_mul(0x9E3779B9) >> 16) as u8;
            }
            let _ = fs::write(path, &rng_buf);
        }
    }
    let _ = fs::remove_file(path);
    eprintln!(
        "[tonkl-prover] Secure deleted: {}",
        path.display()
    );
}

fn default_bb_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".bb/bb")
    } else {
        PathBuf::from("/usr/local/bin/bb")
    }
}

// -- HD key derivation (in-process) -------------------------------------------

fn maybe_apply_hd_derivation(raw_json: &str) -> String {
    let parsed: serde_json::Value = match serde_json::from_str(raw_json) {
        Ok(v) => v,
        Err(_) => return raw_json.to_string(),
    };

    let seed_hex = match parsed.get("_master_seed_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return raw_json.to_string(),
    };

    let indices = match parsed.get("_note_indices") {
        Some(v) => v,
        None => {
            eprintln!(
                "[tonkl-prover] HD mode: _master_seed_hex present but _note_indices missing"
            );
            process::exit(1);
        }
    };

    let seed_bytes = parse_hex_seed(seed_hex);

    let in1_idx = indices["in1"].as_u64().unwrap_or_else(|| {
        eprintln!("[tonkl-prover] HD mode: _note_indices.in1 must be a u64");
        process::exit(1);
    });
    let in2_idx = indices["in2"].as_u64().unwrap_or_else(|| {
        eprintln!("[tonkl-prover] HD mode: _note_indices.in2 must be a u64");
        process::exit(1);
    });

    let in1_sk_hex = derive_note_sk_hex(&seed_bytes, in1_idx);
    let in2_sk_hex = derive_note_sk_hex(&seed_bytes, in2_idx);

    eprintln!(
        "[tonkl-prover] HD mode: derived in1_owner_sk (index {in1_idx}), \
         in2_owner_sk (index {in2_idx})"
    );

    let mut seed_copy = seed_bytes;
    seed_copy.zeroize();

    let mut map = parsed.as_object().cloned().unwrap_or_default();
    map.remove("_master_seed_hex");
    map.remove("_note_indices");
    map.insert(
        "in1_owner_sk".to_string(),
        serde_json::Value::String(in1_sk_hex),
    );
    map.insert(
        "in2_owner_sk".to_string(),
        serde_json::Value::String(in2_sk_hex),
    );

    serde_json::to_string(&map).unwrap_or_else(|e| {
        eprintln!("[tonkl-prover] HD mode: failed to re-serialize JSON: {e}");
        process::exit(1);
    })
}

fn parse_hex_seed(hex_str: &str) -> [u8; 64] {
    let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if clean.len() != 128 {
        eprintln!(
            "[tonkl-prover] HD mode: _master_seed_hex must be 128 hex chars (64 bytes), \
             got {}",
            clean.len()
        );
        process::exit(1);
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| {
            eprintln!("[tonkl-prover] HD mode: invalid hex in _master_seed_hex at byte {i}");
            process::exit(1);
        });
    }
    out
}

// -- Circuit hash verification ------------------------------------------------

fn verify_circuit_hash(circuit_bytes: &[u8]) {
    if EXPECTED_CIRCUIT_HASH == "unchecked" {
        eprintln!(
            "[tonkl-prover] WARNING: circuit hash check is disabled \
             (built without OBSCURA_CIRCUIT_PATH resolvable). \
             Rebuild with the circuit JSON present to enable."
        );
        return;
    }
    let actual = blake3::hash(circuit_bytes);
    let mut actual_hex = String::with_capacity(64);
    for byte in actual.as_bytes() {
        use std::fmt::Write;
        let _ = write!(&mut actual_hex, "{byte:02x}");
    }
    if actual_hex != EXPECTED_CIRCUIT_HASH {
        eprintln!("[tonkl-prover] Circuit hash mismatch -- refusing to run.");
        eprintln!("  expected (compile-time): {EXPECTED_CIRCUIT_HASH}");
        eprintln!("  actual   (runtime)     : {actual_hex}");
        eprintln!("  Rebuild tonkl-prover against the intended circuit.");
        process::exit(1);
    }
    eprintln!("[tonkl-prover] Circuit hash OK ({})", &actual_hex[..16]);
}
