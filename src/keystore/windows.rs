use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{FILETIME, GetLastError, ERROR_NOT_FOUND};
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS,
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
};

const CRED_MAX_CREDENTIAL_BLOB_SIZE: u32 = 2560;

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn cred_target(key_id: &str) -> String {
    format!("delulu-sigil/{key_id}")
}

fn cred_target_pubkey(key_id: &str) -> String {
    format!("delulu-sigil/{key_id}.pub")
}

fn read_blob(target: &str) -> Result<Vec<u8>, String> {
    let target_w = to_wide(target);
    let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();

    unsafe {
        if CredReadW(
            PCWSTR(target_w.as_ptr()),
            CRED_TYPE_GENERIC,
            0,
            &mut cred_ptr,
        )
        .is_err()
        {
            let err = GetLastError();
            if err == ERROR_NOT_FOUND {
                return Err("not found".to_string());
            }
            return Err(format!("CredReadW failed for '{target}': {err:?}"));
        }
    }

    let result = unsafe {
        if cred_ptr.is_null() {
            return Err("CredReadW returned null".to_string());
        }
        let cred = &*cred_ptr;
        if cred.Type != CRED_TYPE_GENERIC {
            return Err("credential is not generic type".to_string());
        }
        if cred.CredentialBlob.is_null() || cred.CredentialBlobSize == 0 {
            return Err("credential blob missing".to_string());
        }
        let mut blob = vec![0u8; cred.CredentialBlobSize as usize];
        std::ptr::copy_nonoverlapping(cred.CredentialBlob, blob.as_mut_ptr(), blob.len());
        Ok(blob)
    };

    unsafe {
        if !cred_ptr.is_null() {
            let cred = &mut *cred_ptr;
            if !cred.CredentialBlob.is_null() && cred.CredentialBlobSize > 0 {
                let size = cred.CredentialBlobSize as usize;
                std::ptr::write_bytes(cred.CredentialBlob, 0, size);
            }
            CredFree(cred_ptr as *const _);
        }
    }

    result
}

fn store_blob(target: &str, blob: &[u8]) -> Result<(), String> {
    let target_w = to_wide(target);
    let username_w = to_wide("delulu-sigil");
    let comment_w = to_wide("delulu-sigil key material");

    let mut blob_vec = blob.to_vec();
    if (blob_vec.len() as u32) > CRED_MAX_CREDENTIAL_BLOB_SIZE {
        return Err("blob too large for Credential Manager".to_string());
    }

    let cred = CREDENTIALW {
        Flags: CRED_FLAGS(0),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_w.as_ptr() as *mut _),
        Comment: PWSTR(comment_w.as_ptr() as *mut _),
        LastWritten: FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        },
        CredentialBlobSize: blob_vec.len() as u32,
        CredentialBlob: blob_vec.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR(std::ptr::null_mut()),
        UserName: PWSTR(username_w.as_ptr() as *mut _),
    };

    unsafe {
        match CredWriteW(&cred, 0) {
            Ok(_) => {
                for b in blob_vec.iter_mut() {
                    *b = 0;
                }
                Ok(())
            }
            Err(e) => {
                for b in blob_vec.iter_mut() {
                    *b = 0;
                }
                Err(format!("CredWriteW failed for '{target}': {e}"))
            }
        }
    }
}

fn delete_blob(target: &str) -> Result<(), String> {
    let target_w = to_wide(target);
    unsafe {
        match CredDeleteW(PCWSTR(target_w.as_ptr()), CRED_TYPE_GENERIC, 0) {
            Ok(_) => Ok(()),
            Err(_) => {
                let err = GetLastError();
                if err == ERROR_NOT_FOUND {
                    Ok(())
                } else {
                    Err(format!("CredDeleteW failed for '{target}': {err:?}"))
                }
            }
        }
    }
}

pub fn read_seed(key_id: &str) -> Result<[u8; 32], String> {
    let target = cred_target(key_id);
    let blob = match read_blob(&target) {
        Ok(b) => b,
        Err(e) => {
            if e.contains("not found") {
                return Err(format!(
                    "no key in Windows Credential Manager for key-id '{key_id}' (target '{target}'). Run 'delulu-sigil keygen --key-id {key_id} --new' after importing."
                ));
            }
            return Err(e);
        }
    };
    if blob.len() != 32 {
        return Err(format!("credential blob size is {} (expected 32 bytes)", blob.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&blob);
    Ok(seed)
}

pub fn read_pubkey_hex(key_id: &str) -> Result<String, String> {
    let target = cred_target_pubkey(key_id);
    let blob = match read_blob(&target) {
        Ok(b) => b,
        Err(e) => {
            if e.contains("not found") {
                return Err(format!(
                    "no public key in Windows Credential Manager for key-id '{key_id}' (target '{target}')."
                ));
            }
            return Err(e);
        }
    };
    Ok(hex::encode(blob))
}

pub fn store_seed(key_id: &str, seed: &[u8; 32]) -> Result<(), String> {
    store_blob(&cred_target(key_id), seed)
}

pub fn store_pubkey_bytes(key_id: &str, pubkey: &[u8; 32]) -> Result<(), String> {
    store_blob(&cred_target_pubkey(key_id), pubkey)
}

pub fn delete_keypair(key_id: &str) -> Result<(), String> {
    let _ = delete_blob(&cred_target(key_id));
    let _ = delete_blob(&cred_target_pubkey(key_id));
    Ok(())
}

pub fn generate_and_store(key_id: &str, replace: bool) -> Result<([u8; 32], [u8; 32]), String> {
    if !replace {
        match read_seed(key_id) {
            Ok(_) => {
                return Err(format!(
                    "key '{key_id}' already exists in Credential Manager. Use --new to overwrite."
                ))
            }
            Err(e) => {
                if !e.contains("no key in Windows Credential Manager") {
                    return Err(e);
                }
            }
        }
    } else {
        let _ = delete_keypair(key_id);
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS randomness unavailable: {e}"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    let pubkey = verifying.to_bytes();

    store_seed(key_id, &seed)?;
    store_pubkey_bytes(key_id, &pubkey)?;
    Ok((seed, pubkey))
}
