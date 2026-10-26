//! Keypair generation for manifest signing. Keys are stored in OS keystore.

use sha2::{Digest, Sha256};

use crate::keystore;

/// `delulu-sigil keygen` — generate a fresh ed25519 keypair and store in Windows Credential Manager.
pub fn run(key_id: &str, new: bool) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = (key_id, new);
        return Err("Windows Credential Manager is required".to_string());
    }

    #[cfg(windows)]
    {
        let (_seed, pubkey) = keystore::generate_and_store(key_id, new)?;
        let public_hex = hex::encode(pubkey);
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        let fp = hex::encode(&hasher.finalize()[..8]);

        println!("key id:     {key_id}");
        println!("public key: {public_hex}");
        println!("fingerprint: sha256:{fp}");
        println!();
        println!("Pin this public key in the host (OFFICIAL_PUBLISHER_KEYS):");
        println!("    (");
        println!("        \"{key_id}\",");
        println!("        \"{public_hex}\",");
        println!("    ),");
        Ok(())
    }
}
