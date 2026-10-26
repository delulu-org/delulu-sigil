//! OS keystore abstraction. Windows uses Credential Manager.
#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::{generate_and_store, read_pubkey_hex, read_seed};

#[cfg(not(windows))]
pub fn read_seed(_key_id: &str) -> Result<[u8; 32], String> {
    Err("Windows Credential Manager is required for signing on this platform".to_string())
}

#[cfg(not(windows))]
pub fn read_pubkey_hex(_key_id: &str) -> Result<String, String> {
    Err("Windows Credential Manager is required for signing on this platform".to_string())
}

#[cfg(not(windows))]
pub fn generate_and_store(key_id: &str, replace: bool) -> Result<([u8; 32], [u8; 32]), String> {
    let _ = (key_id, replace);
    Err("Windows Credential Manager is required for signing on this platform".to_string())
}
