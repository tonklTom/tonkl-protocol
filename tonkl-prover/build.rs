//! Build script for tonkl-prover.
//!
//! Computes a BLAKE3 hash of the compiled circuit JSON and bakes it into
//! the binary as the `TONKL_CIRCUIT_HASH` env var. The runtime then
//! compares against this constant and refuses to run if the circuit has
//! been swapped between `nargo compile` and `tonkl-prover`.
//!
//! Circuit path resolution (first hit wins):
//!   1. $TONKL_CIRCUIT_PATH (absolute or relative to the prover crate root)
//!   2. ../tonkl-transfer/target/tonkl_transfer.json  (default)
//!
//! If the file doesn't exist at build time, the build fails closed. For local
//! development only, set `TONKL_ALLOW_UNCHECKED_CIRCUIT_HASH=1` to bake the
//! literal string "unchecked"; runtime will still require the same opt-in
//! before skipping the hash check.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR always set by cargo");

    // Resolve circuit path: env override wins, else default.
    let circuit_path: PathBuf = match env::var("TONKL_CIRCUIT_PATH") {
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
            .join("tonkl-transfer")
            .join("target")
            .join("tonkl_transfer.json"),
    };

    // Tell cargo when to re-run this build script.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=TONKL_CIRCUIT_PATH");
    println!("cargo:rerun-if-env-changed=TONKL_ALLOW_UNCHECKED_CIRCUIT_HASH");
    println!("cargo:rerun-if-changed={}", circuit_path.display());

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
        Err(e) => {
            let allow_unchecked = env::var("TONKL_ALLOW_UNCHECKED_CIRCUIT_HASH")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !allow_unchecked {
                panic!(
                    "tonkl-prover: required circuit artifact not found at {} ({e}). \
Run `cd {}/../tonkl-transfer && nargo compile`, set TONKL_CIRCUIT_PATH to the intended circuit JSON, \
or set TONKL_ALLOW_UNCHECKED_CIRCUIT_HASH=1 for local development only.",
                    circuit_path.display(),
                    manifest_dir,
                );
            }

            println!(
                "cargo:warning=tonkl-prover: circuit not found at {} — baking 'unchecked' because TONKL_ALLOW_UNCHECKED_CIRCUIT_HASH is set",
                circuit_path.display()
            );
            "unchecked".to_string()
        }
    };

    println!("cargo:rustc-env=TONKL_CIRCUIT_HASH={hash_hex}");
    println!(
        "cargo:rustc-env=TONKL_CIRCUIT_HASH_SOURCE={}",
        circuit_path.display()
    );
}
