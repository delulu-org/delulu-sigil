//! Signing: the exact bytes covered, and the ed25519 operations.
//!
//! What gets signed — and therefore what a verifier MUST reproduce — is:
//!
//! ```text
//! PAYLOAD_DOMAIN || manifest.canonical_payload()
//! ```
//!
//! where `canonical_payload()` is `dad_local_core`'s definition (the typed
//! manifest as compact, key-sorted JSON with the `signature` key removed).
//! The domain prefix is domain separation: it stops this key from ever
//! validating a byte string that was produced for some other protocol or
//! purpose. The host's verifier must prepend the identical [`PAYLOAD_DOMAIN`].

use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use dad_local_core::LocalAddonManifest;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Domain-separation tag prepended to every signed payload. Bumping this
/// string invalidates every existing signature — that is the point.
pub const PAYLOAD_DOMAIN: &[u8] = b"dad-local-manifest-v1\0";

fn read_manifest(path: &Path) -> Result<(Value, LocalAddonManifest), String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    let manifest = LocalAddonManifest::parse(&value).map_err(|errors| {
        format!(
            "{} failed contract validation:\n  - {}",
            path.display(),
            errors.join("\n  - ")
        )
    })?;
    Ok((value, manifest))
}

/// The exact bytes a signature covers for `manifest`.
pub fn signing_payload(manifest: &LocalAddonManifest) -> Result<Vec<u8>, String> {
    let canonical = manifest
        .canonical_payload()
        .map_err(|e| format!("failed to canonicalize manifest: {e}"))?;
    let mut payload = Vec::with_capacity(PAYLOAD_DOMAIN.len() + canonical.len());
    payload.extend_from_slice(PAYLOAD_DOMAIN);
    payload.extend_from_slice(&canonical);
    Ok(payload)
}

/// Lowercase hex SHA-256 of a file's bytes.
pub fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn key_bytes_32(hex_str: &str, what: &str) -> Result<[u8; 32], String> {
    let trimmed = hex_str.trim();
    let bytes = hex::decode(trimmed).map_err(|_| format!("{what} must be hex"))?;
    bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{what} must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })
}

/// Parse a 32-byte hex public key into a verifying key.
pub fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let bytes = key_bytes_32(hex_str, "public key")?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("invalid public key: {e}"))
}

/// Sign `manifest` and return the standard-base64 signature.
pub fn sign(manifest: &LocalAddonManifest, key: &SigningKey) -> Result<String, String> {
    let payload = signing_payload(manifest)?;
    Ok(STANDARD.encode(key.sign(&payload).to_bytes()))
}

/// Verify `manifest.signature` against `key`.
pub fn verify(manifest: &LocalAddonManifest, key: &VerifyingKey) -> Result<(), String> {
    let payload = signing_payload(manifest)?;
    let raw = dad_local_core::validation::decode_standard_base64(&manifest.signature)?;
    let signature =
        Signature::from_slice(&raw).map_err(|_| "signature must be 64 bytes".to_string())?;
    key.verify(&payload, &signature)
        .map_err(|_| "signature verification failed".to_string())
}

fn resolve_signing_key_from_store(key_id: &str) -> Result<SigningKey, String> {
    #[cfg(windows)]
    {
        let seed = crate::keystore::read_seed(key_id)?;
        let key = SigningKey::from_bytes(&seed);
        // zeroize seed copy
        let mut zero = seed;
        for b in zero.iter_mut() {
            *b = 0;
        }
        Ok(key)
    }
    #[cfg(not(windows))]
    {
        let _ = key_id;
        Err("Windows Credential Manager is required for signing".to_string())
    }
}

fn resolve_verifying_key(
    pubkey_hex: Option<&str>,
    pubkey_file: Option<&Path>,
) -> Result<VerifyingKey, String> {
    let source = match (pubkey_hex, pubkey_file) {
        (Some(h), _) => h.to_string(),
        (None, Some(f)) => std::fs::read_to_string(f)
            .map_err(|e| format!("cannot read public key file {}: {e}", f.display()))?,
        (None, None) => std::env::var("DELULU_VERIFY_PUBKEY").map_err(|_| {
            "no public key: pass --pubkey-hex, --pubkey-file, or set $DELULU_VERIFY_PUBKEY"
                .to_string()
        })?,
    };
    parse_verifying_key(&source)
}

fn parse_artifact(spec: &str) -> Result<(String, std::path::PathBuf), String> {
    let (platform, path) = spec
        .split_once('=')
        .ok_or_else(|| format!("--artifact must be PLATFORM=PATH, got '{spec}'"))?;
    if platform.is_empty() || path.is_empty() {
        return Err(format!("--artifact must be PLATFORM=PATH, got '{spec}'"));
    }
    Ok((platform.to_string(), std::path::PathBuf::from(path)))
}

/// `delulu-sigil sign` — hash artifacts, sign, write the signed manifest.
#[allow(clippy::too_many_arguments)]
pub fn run_sign(
    manifest_path: &Path,
    artifacts: &[String],
    key_id: &str,
    out: Option<&Path>,
    repo: Option<&str>,
    tag: Option<&str>,
) -> Result<(), String> {
    let (_raw_value, mut manifest) = read_manifest(manifest_path)?;
    let key = resolve_signing_key_from_store(key_id)?;

    let derived_tag = match (repo, tag) {
        (Some(_), None) => Some(format!("v{}", manifest.version)),
        (_, explicit) => explicit.map(str::to_string),
    };

    for spec in artifacts {
        let (platform, path) = parse_artifact(spec)?;
        let hash = sha256_hex(&path)?;
        let asset = manifest
            .platform_assets
            .get_mut(&platform)
            .ok_or_else(|| format!("manifest has no platform_assets entry '{platform}'"))?;

        asset.sha256 = hash.clone();
        if let Some(repo) = repo {
            let tag = derived_tag
                .as_deref()
                .ok_or_else(|| "internal: derived tag missing".to_string())?;
            asset.download_url = format!(
                "https://github.com/{repo}/releases/download/{tag}/{}",
                asset.binary_name
            );
        }
        println!("  {platform:<16} sha256 {hash}");
    }

    manifest.signature = sign(&manifest, &key)?;

    let out_value = serde_json::to_value(&manifest)
        .map_err(|e| format!("failed to serialize signed manifest: {e}"))?;
    let check = dad_local_core::validate_manifest(&out_value);
    if !check.valid {
        return Err(format!(
            "signed manifest failed release-state validation:\n  - {}",
            check.errors.join("\n  - ")
        ));
    }

    let dest = out.unwrap_or(manifest_path);
    let pretty = serde_json::to_string_pretty(&out_value)
        .map_err(|e| format!("failed to format manifest: {e}"))?;
    std::fs::write(dest, format!("{pretty}\n"))
        .map_err(|e| format!("cannot write {}: {e}", dest.display()))?;

    println!(
        "signed {} v{} -> {}",
        manifest.id,
        manifest.version,
        dest.display()
    );
    Ok(())
}

/// `delulu-sigil verify` — recompute the payload and check the signature.
pub fn run_verify(
    manifest_path: &Path,
    pubkey_hex: Option<&str>,
    pubkey_file: Option<&Path>,
) -> Result<(), String> {
    let (_raw_value, manifest) = read_manifest(manifest_path)?;
    if manifest.signature.trim().is_empty() {
        return Err(format!(
            "{} is unsigned (authoring state)",
            manifest_path.display()
        ));
    }
    let key = resolve_verifying_key(pubkey_hex, pubkey_file)?;
    verify(&manifest, &key)?;
    println!("signature OK for {} v{}", manifest.id, manifest.version);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> LocalAddonManifest {
        LocalAddonManifest::parse(&json!({
            "id": "org.example.test",
            "name": "Test",
            "version": "1.0.0",
            "type": "local",
            "protocol_version": "2.0",
            "capabilities": ["meta"],
            "platform_assets": {
                "windows-x64": {
                    "download_url": "https://example.com/a.exe",
                    "binary_name": "a.exe",
                    "sha256": "ab".repeat(32),
                    "entry_command": "rpc"
                }
            },
            "signature": ""
        }))
        .expect("fixture must be a valid manifest")
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn payload_is_the_domain_offset_by_the_canonical_bytes() {
        let manifest = fixture();
        let payload = signing_payload(&manifest).unwrap();
        assert!(payload.starts_with(PAYLOAD_DOMAIN));
        assert_eq!(
            &payload[PAYLOAD_DOMAIN.len()..],
            manifest.canonical_payload().unwrap().as_slice()
        );
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let key = key();
        let mut manifest = fixture();
        manifest.signature = sign(&manifest, &key).unwrap();
        verify(&manifest, &key.verifying_key()).expect("a signature we made must verify");
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let mut manifest = fixture();
        manifest.signature = sign(&manifest, &key()).unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert!(verify(&manifest, &other.verifying_key()).is_err());
    }

    #[test]
    fn changing_any_field_invalidates_the_signature() {
        let key = key();
        for mutate in [
            (|m: &mut LocalAddonManifest| m.version = "1.0.1".to_string())
                as fn(&mut LocalAddonManifest),
            |m: &mut LocalAddonManifest| m.name = "Renamed".to_string(),
            |m: &mut LocalAddonManifest| {
                m.platform_assets.get_mut("windows-x64").unwrap().sha256 = "0".repeat(64)
            },
            |m: &mut LocalAddonManifest| {
                m.platform_assets
                    .get_mut("windows-x64")
                    .unwrap()
                    .download_url = "https://evil.example.com/x.exe".to_string()
            },
        ] {
            let mut manifest = fixture();
            manifest.signature = sign(&manifest, &key).unwrap();
            mutate(&mut manifest);
            assert!(
                verify(&manifest, &key.verifying_key()).is_err(),
                "a signed manifest must reject any field change"
            );
        }
    }

    #[test]
    fn key_parsing_requires_exactly_32_bytes() {
        assert!(parse_verifying_key("abcd").is_err());
        assert!(parse_verifying_key("zz").is_err());
        assert!(parse_verifying_key(&hex::encode([0u8; 32])).is_ok());
    }
}
