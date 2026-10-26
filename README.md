# delulu-sigil

The official cryptographic manifest signer and integrity verification tool for Delulu local addons (`DAD protocol v2.0`).

---

## What is this?

**Delulu Sigil** (`delulu-sigil`) is the cryptographic gatekeeping and manifest-signing tool for Delulu local addons (`DAD protocol v2.0`).

To be completely clear: **Delulu does not build or author these third-party addons.** Local addons are created independently by selected developers and teams.

Because local addons execute directly on a user's machine as spawned processes, running arbitrary native code presents severe risks—malware, token exfiltration, unauthorized OS tampering, or illicit background activity. To ensure that **nothing harmful or unauthorized ever touches Delulu or our users' devices**, the Delulu team acts strictly as an independent auditor and gatekeeper:

1. **Source Code Review:** Selected addon authors submit their source trees. We review and audit the code to ensure sandboxing compliance, zero telemetry, zero credential harvesting, and strict adherence to the DAD protocol.
2. **Deterministic Fingerprinting:** Once an addon passes review, Sigil hashes each compiled platform binary (`sha256`) and binds the release asset destination.
3. **Cryptographic Permission Grant:** Sigil signs the canonical manifest with Delulu's private key.

The signature is not a claim of authorship—it is a **cryptographic seal of approval and permission**, stating: *"We have reviewed this developer's source code, confirmed it is safe and clean, and authorized this exact, un-tampered binary to run inside Delulu."*

---

## Why is this open source?

If local addons are not open for arbitrary public authoring, why is this tool public?

### The short answer: Transparency, community auditing, and trust.

Delulu Core divides addons into two distinct architectures:

* **HTTP Addons (Open Community Ecosystem):** Remote web services running outside the client application. These are **100% open** for any developer to build, test, and distribute to the public registry using `@delulu-addon/dad-sdk`.
* **Local Addons (Native Binaries):** High-performance modules executing natively on the user's OS. These require strict isolation and audit gating.

We do not believe in opaque "trust me" binaries. We open-sourced `delulu-sigil` and [`dad-sdk-local`](https://github.com/delulu-org/dad-sdk-local) so anyone can:
1. **Audit the Verification Logic:** Inspect exactly how manifests are canonicalized, domain-separated (`dad-local-manifest-v1`), and cryptographically bound.
2. **Verify Independence:** Confirm that the signer does nothing hidden—no telemetry, no tracking, just standard Ed25519 cryptography and SHA-256 binary validation.
3. **Verify Addons Independently:** Anyone in the community can use `delulu-sigil verify` to independently verify that any signed addon release in the wild matches our published public keys and has not been modified or tampered with.

---

## How the signature works

A signature is only as secure as the bytes it covers. Delulu Sigil uses **deterministic canonicalization** and **domain separation**:

```text
PAYLOAD_DOMAIN || manifest.canonical_payload()
```

1. **Domain Separation:** Every payload is prepended with `b"dad-local-manifest-v1\0"`. This prevents cross-protocol signature reuse.
2. **Canonical JSON Serialization:** The typed manifest struct is serialized into compact JSON with:
   - Sorted keys.
   - The `"signature"` field stripped entirely.
   - Absent optional fields omitted (not serialized as `null`).
3. **Binary Binding:** The signed manifest contains the exact `sha256` hex of each platform executable (`windows-x64`, etc.) and the exact `download_url`. If a binary is modified by even one byte, the SHA-256 check fails. If the manifest text is altered, the Ed25519 signature fails.

---

## CLI Reference

See [USAGE.md](USAGE.md) for full details. Current behavior (Windows Credential Manager):

### 1. Sign a manifest

Takes an authoring-state `manifest.json`, calculates the binary SHA-256, fills in the GitHub release download URL (if `--repo`), signs the canonical payload from the key in Windows Credential Manager, and rewrites the manifest in place:

```bash
delulu-sigil sign \
  --manifest path/to/manifest.json \
  --artifact windows-x64=target/release/addon.exe \
  --key-id delulu-official-v2 \
  --repo your-org/your-repo \
  --tag addon-v0.1.0
```

### 2. Verify a signed manifest

Verifies that the signature in `manifest.json` is mathematically valid for the declared fields against a given public key:

```bash
delulu-sigil verify \
  --manifest path/to/manifest.json \
  --pubkey-file path/to/signing.public
```

Or with hex directly:

```bash
delulu-sigil verify \
  --manifest path/to/manifest.json \
  --pubkey-hex <32-byte-hex-public-key>
```

Output:
```
signature OK for org.example.addon v0.1.0
```

### 3. Generate a keypair

Generates a fresh cryptographically secure Ed25519 keypair and stores it in Windows Credential Manager. The private key is never written to disk or printed:

```bash
delulu-sigil keygen --key-id my-signing-key
```

Use `--new` to overwrite an existing key. Prints the public key and a host pinning snippet.

---

## Project Structure

```
delulu_sigil/
├── Cargo.toml
├── README.md
├── USAGE.md
├── .gitignore
├── scripts/
│   └── import-key-to-credman.ps1  # Manual import helper (not run by binary)
└── src/
    ├── main.rs           # CLI entry point (clap)
    ├── keygen.rs         # Keypair generation routine
    ├── keystore/         # OS keystore (Windows Credential Manager)
    └── signing.rs        # Canonicalization, hashing, Ed25519 sign & verify
```

---

## Building from source

Requirements: Modern Rust toolchain.

```bash
# Clone the repository
git clone https://github.com/delulu-org/delulu-sigil.git
cd delulu-sigil

# Run test suite
cargo test

# Build optimized release binary
cargo build --release

# Or build and install the CLI onto your PATH (available as `delulu-sigil`)
cargo install --path .
```

The compiled binary will be placed at `target/release/delulu-sigil.exe` (or `target/release/delulu-sigil` on other platforms). 

Note: Signing/keygen requires Windows Credential Manager. Verification with a public key can work on other platforms.

---

## License

MIT License. Developed for the Delulu ecosystem.
