//! Build script for obscura-prover.
//!
//! Computes a BLAKE3 hash of the compiled circuit JSON and bakes it into
//! the binary as the `OBSCURA_CIRCUIT_HASH` env var. The runtime then
//! compares against this constant and refuses to run if the circuit has
//! been swapped between `nargo compile` and `obscura-prover`.
//!
//! Circuit path resolution (first hit wins):
//!   1. $OBSCURA_CIRCUIT_PATH (absolute or relative to the prover crate root)
//!   2. ../obscura-transfer/target/obscura_transfer.json  (default)
//!
//! If the file doesn't exist at build time, the baked hash is the literal
//! string "unchecked" and the runtime check is skipped with a warning.
//! This keeps `cargo check` / `cargo test` working on a fresh checkout
//! before `nargo compile` has been run.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR always set by cargo");

    // Resolve circuit path: env override wins, else default.
    let circuit_path: PathBuf = match env::var("OBSCURA_CIRCUIT_PATH") {
        Ok(p) => {
            let pb = PathBuf::from(&p);
            if pb.is_absolute() {
                pb
            } else {
                PathBuf::from(&manifest_dir).join(pb)
            }
        }
        Err(_) => PathBuf::from(&manifest_dir)
            .parent()
            .expect("crate has a parent dir")
            .join("obscura-transfer")
            .join("target")
            .join("obscura_transfer.json"),
    };

    // Tell cargo when to re-run this build script.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=OBSCURA_CIRCUIT_PATH");
    println!(
        "cargo:rerun-if-changed={}",
        circuit_path.display()
    );

    let hash_hex = match fs::read(&circuit_path) {
        Ok(bytes) => {
            let h = blake3::hash(&bytes);
            // BLAKE3's to_hex returns an ArrayString; we want a fixed lower-hex str.
            let mut s = String::with_capacity(64);
            for byte in h.as_bytes() {
                use std::fmt::Write;
                let _ = write!(&mut s, "{byte:02x}");
            }
            s
        }
        Err(_) => {
            // Emit a build-time warning so the user knows the hash check is disabled.
            println!(
                "cargo:warning=obscura-prover: circuit not found at {} — baking 'unchecked' (runtime hash check disabled)",
                circuit_path.display()
            );
            "unchecked".to_string()
        }
    };

    println!("cargo:rustc-env=OBSCURA_CIRCUIT_HASH={hash_hex}");
    println!(
        "cargo:rustc-env=OBSCURA_CIRCUIT_HASH_SOURCE={}",
        circuit_path.display()
    );
}
