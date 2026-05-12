// Tonkl Protocol - Proof Verifier
//
// Verifies UltraHonk ZK proofs by shelling out to `bb verify`.
//
// Each circuit type (transfer, merge, split, mint) has a pre-generated
// verification key (VK). When a transaction is submitted, the node:
//   1. Writes the proof and public_inputs to temp files
//   2. Calls `bb verify -k <vk> -p <proof> -i <public_inputs>`
//   3. Accepts or rejects based on the exit code
//
// VK files are loaded once at startup from a configured directory.

use crate::block::TxType;
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tracing::{info, warn};

// ─────────────────────────────────────────────────────────────────────
// Verifier
// ─────────────────────────────────────────────────────────────────────

/// Holds verification keys for each circuit type and handles proof verification.
pub struct ProofVerifier {
    /// Path to the `bb` binary
    bb_path: PathBuf,
    /// Verification keys indexed by transaction type
    vk_map: HashMap<TxType, Vec<u8>>,
    /// Whether verification is enabled (can be disabled for testing)
    enabled: bool,
}

impl ProofVerifier {
    /// Create a verifier with no VKs loaded (verification disabled).
    pub fn disabled() -> Self {
        Self {
            bb_path: PathBuf::from("bb"),
            vk_map: HashMap::new(),
            enabled: false,
        }
    }

    /// Create a verifier by loading VKs from the circuit directories.
    ///
    /// Expected layout:
    ///   vk_dir/transfer/vk   (or transfer.vk)
    ///   vk_dir/merge/vk
    ///   vk_dir/split/vk
    ///   vk_dir/mint/vk
    ///
    /// Missing VKs are logged as warnings but don't prevent startup.
    /// Transactions for circuit types without a loaded VK will be rejected.
    pub fn from_vk_dir(vk_dir: &Path, bb_path: &str) -> Result<Self, String> {
        let mut vk_map = HashMap::new();

        let circuits = [
            (TxType::Transfer, "transfer"),
            (TxType::Merge, "merge"),
            (TxType::Split, "split"),
            (TxType::Mint, "mint"),
        ];

        for (tx_type, name) in &circuits {
            // Try: vk_dir/<name>/vk (matches bb write_vk output layout)
            let vk_path = vk_dir.join(name).join("vk");
            if vk_path.exists() {
                let bytes = std::fs::read(&vk_path)
                    .map_err(|e| format!("failed to read VK at {}: {}", vk_path.display(), e))?;
                info!("Loaded VK for {}: {} bytes", name, bytes.len());
                vk_map.insert(*tx_type, bytes);
                continue;
            }

            // Try: vk_dir/<name>.vk (flat layout)
            let vk_path_flat = vk_dir.join(format!("{}.vk", name));
            if vk_path_flat.exists() {
                let bytes = std::fs::read(&vk_path_flat).map_err(|e| {
                    format!("failed to read VK at {}: {}", vk_path_flat.display(), e)
                })?;
                info!("Loaded VK for {}: {} bytes", name, bytes.len());
                vk_map.insert(*tx_type, bytes);
                continue;
            }

            warn!(
                "No VK found for {} circuit (checked {} and {})",
                name,
                vk_path.display(),
                vk_path_flat.display()
            );
        }

        if vk_map.is_empty() {
            warn!("No verification keys loaded — all proof verification will fail");
        }

        Ok(Self {
            bb_path: PathBuf::from(bb_path),
            vk_map,
            enabled: true,
        })
    }

    /// Check if verification is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Number of loaded VKs.
    pub fn loaded_vk_count(&self) -> usize {
        self.vk_map.len()
    }

    /// Verify a proof for the given transaction type.
    ///
    /// Returns Ok(()) if the proof is valid, Err(message) if invalid or
    /// verification could not be performed.
    pub fn verify(
        &self,
        tx_type: TxType,
        proof: &[u8],
        public_inputs: &[u8],
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let vk = self
            .vk_map
            .get(&tx_type)
            .ok_or_else(|| format!("no verification key loaded for {:?} circuit", tx_type))?;

        // Create temp directory for verification artifacts
        let tmp = TempDir::new().map_err(|e| format!("failed to create temp dir: {}", e))?;

        let vk_path = tmp.path().join("vk");
        let proof_path = tmp.path().join("proof");
        let inputs_path = tmp.path().join("public_inputs");

        // Write artifacts to temp files
        write_file(&vk_path, vk)?;
        write_file(&proof_path, proof)?;
        write_file(&inputs_path, public_inputs)?;

        // Run bb verify
        let output = Command::new(&self.bb_path)
            .args([
                "verify",
                "-k",
                &vk_path.to_string_lossy(),
                "-p",
                &proof_path.to_string_lossy(),
                "-i",
                &inputs_path.to_string_lossy(),
            ])
            .output()
            .map_err(|e| format!("failed to execute bb verify: {} (is bb in PATH?)", e))?;

        // Temp dir is automatically cleaned up when `tmp` drops

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(format!(
                "proof verification failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ))
        }
    }
}

/// Write bytes to a file.
fn write_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut f = std::fs::File::create(path)
        .map_err(|e| format!("failed to create {}: {}", path.display(), e))?;
    f.write_all(data)
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Public Input Serialization
// ─────────────────────────────────────────────────────────────────────

/// Serialize public inputs from hex strings to the binary format bb expects.
///
/// bb's public_inputs file is a sequence of 32-byte big-endian field elements,
/// one per public input, concatenated with no delimiters.
pub fn serialize_public_inputs(hex_inputs: &[String]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(hex_inputs.len() * 32);
    for (i, hex_str) in hex_inputs.iter().enumerate() {
        let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let decoded =
            hex::decode(clean).map_err(|e| format!("invalid hex in public_input[{}]: {}", i, e))?;
        if decoded.len() > 32 {
            return Err(format!(
                "public_input[{}] too large: {} bytes",
                i,
                decoded.len()
            ));
        }
        // Left-pad to 32 bytes
        let mut padded = [0u8; 32];
        padded[32 - decoded.len()..].copy_from_slice(&decoded);
        bytes.extend_from_slice(&padded);
    }
    Ok(bytes)
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_verifier_always_passes() {
        let v = ProofVerifier::disabled();
        assert!(!v.is_enabled());
        assert!(v.verify(TxType::Transfer, &[], &[]).is_ok());
        assert!(v.verify(TxType::Mint, &[], &[]).is_ok());
    }

    #[test]
    fn test_serialize_public_inputs_basic() {
        let inputs = vec![
            "0x0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            "0x00000000000000000000000000000000000000000000000000000000000000ff".to_string(),
        ];
        let bytes = serialize_public_inputs(&inputs).unwrap();
        assert_eq!(bytes.len(), 64); // 2 * 32 bytes
        assert_eq!(bytes[31], 0x01);
        assert_eq!(bytes[63], 0xff);
    }

    #[test]
    fn test_serialize_public_inputs_short_hex() {
        // Short hex should be left-padded to 32 bytes
        let inputs = vec!["0xff".to_string()];
        let bytes = serialize_public_inputs(&inputs).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 0xff);
        assert!(bytes[..31].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_serialize_public_inputs_no_prefix() {
        let inputs = vec!["01".to_string()];
        let bytes = serialize_public_inputs(&inputs).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[31], 0x01);
    }

    #[test]
    fn test_serialize_public_inputs_empty() {
        let bytes = serialize_public_inputs(&[]).unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_verifier_rejects_missing_vk() {
        let v = ProofVerifier {
            bb_path: PathBuf::from("bb"),
            vk_map: HashMap::new(),
            enabled: true,
        };
        let result = v.verify(TxType::Transfer, &[0u8; 32], &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no verification key"));
    }
}
