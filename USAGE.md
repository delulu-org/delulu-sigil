# delulu-sigil Usage

This document describes the current CLI. Commands and flags reflect the Windows Credential Manager-backed implementation.

## Commands

### `delulu-sigil keygen`
Generate a fresh Ed25519 keypair and store it in Windows Credential Manager. The private key is never written to disk or printed.

```
delulu-sigil keygen [--key-id <id>] [--new]
```

Options:
- `--key-id <id>` (default: `delulu-official-v2`) - Credential Manager target name key id.
- `--new` - Overwrite an existing key in the store.

Output: prints `key id`, `public key`, `fingerprint`, and a host pinning snippet. No private key is emitted.

### `delulu-sigil sign`
Hash platform binaries, optionally derive GitHub release download URLs, sign the manifest, and write the signed manifest. Reads the private key from Windows Credential Manager.

```
delulu-sigil sign \
  --manifest <path> \
  --artifact <PLATFORM>=<PATH> [--artifact ...] \
  [--key-id <id>] \
  [--out <path>] \
  [--repo <owner/repo>] \
  [--tag <tag>]
```

Options:
- `--manifest <path>` (required) - Path to authoring-state `manifest.json`
- `--artifact <PLATFORM>=<PATH>` (required, one or more) - Must correspond to entries in `platform_assets`
- `--key-id <id>` (default: `delulu-official-v2`) - Key id in Windows Credential Manager
- `--out <path>` - Output path; defaults to rewriting input manifest in place
- `--repo <owner/repo>` - Enables derived `download_url` for GitHub releases (URL is signed)
- `--tag <tag>` - Tag for derived URLs; defaults to `v{version}`

Behavior:
- Computes SHA-256 of each artifact and writes to `platform_assets[platform].sha256`
- If `--repo` provided, sets `platform_assets[platform].download_url = https://github.com/{repo}/releases/download/{tag}/{binary_name}`
- Signs the canonical payload (`dad-local-manifest-v1\0 || manifest.canonical_payload()` with signature stripped)
- Validates the signed manifest against the DAD contract
- Writes the signed manifest

### `delulu-sigil verify`
Verify a signed manifest against a public key.

```
delulu-sigil verify \
  --manifest <path> \
  [--pubkey-hex <32-byte-hex>] \
  [--pubkey-file <path>]
```

Options:
- `--manifest <path>` (required)
- `--pubkey-hex <32-byte-hex>` - Public key as hex
- `--pubkey-file <path>` - File containing 32-byte hex public key

Public key can also be provided via `DELULU_VERIFY_PUBKEY` if neither flag is given (see `signing.rs` for current behavior).

Output:
```
signature OK for <id> v<version>
```

## Key storage

- Private keys are stored in **Windows Credential Manager** only (generic credential, `CRED_PERSIST_LOCAL_MACHINE`). 
- No private key files are read/written by the tool. No private key is ever printed.
- Public keys are not secrets; they may be shared/pinned.

### Manual import of existing key
If you already have a private key outside the repo (e.g. `C:\Users\Sparsho\.delulu\keys\delulu-official-v2.private`), import it manually with `scripts/import-key-to-credman.ps1`. Do **not** run file-to-store logic inside this binary.

## Notes
- The signature binds `sha256` and `download_url` inside the manifest. Any change invalidates the signature.
- Domain separation: `dad-local-manifest-v1\0` prefix.
- Uses `dad-local-core` from `https://github.com/delulu-org/dad-sdk-local` at tag `v0.1.1`.
- Windows only for signing/keygen (Credential Manager). Verification can work with pubkeys on other platforms.
- No telemetry, no network calls except when using git deps/Cargo.
