# GhostID CLI — Help

> Encrypt any folder on your drive. No account. No server. Your key, your data.

**Version:** 0.1.0
**License:** Apache 2.0

---

## What GhostID Does

GhostID encrypts entire folders into unreadable `.ghost` blobs. No filenames, no folder structure, no readable content — just binary noise. The only thing that can reverse it is the passphrase you set.

There is no account. There is no server. There is no recovery. If you lose your passphrase, your data is gone. That is the design.

---

## Installation

GhostID is a Rust binary. Build from source:

```
cd ghostid-cli
cargo build --release
```

The binary lands at `target/release/ghostid`. To make it available system-wide:

```
sudo ln -s /full/path/to/ghostid-cli/target/release/ghostid /usr/local/bin/ghostid
```

Verify:

```
ghostid --version
```

---

## Commands

### `ghostid encrypt`

Encrypt a folder into GhostID format.

**To a separate location:**

```
ghostid encrypt --source <FOLDER> --target <OUTPUT>
```

**In place (replaces the original):**

```
ghostid encrypt --source <FOLDER> --in-place
```

In-place mode is safe — it encrypts to a staging area, verifies a full round-trip decrypt, compares every file byte-for-byte against the original, and only replaces the folder if verification passes. If anything fails, your original folder is untouched.

**Options:**

| Flag | Description |
|---|---|
| `-s, --source <PATH>` | Path to the folder to encrypt (required) |
| `-t, --target <PATH>` | Path for the encrypted output directory |
| `--in-place` | Encrypt in place (cannot be used with `--target`) |
| `-p, --passphrase <TEXT>` | Passphrase (omit to be prompted — recommended) |

**Passphrase rules:**

- Minimum 12 characters — enforced, no exceptions
- Longer is stronger — try a sentence you'll remember
- Omit `-p` to be prompted securely (keeps it out of shell history)

---

### `ghostid decrypt`

Decrypt a GhostID directory back to its original form. Full permanent export.

```
ghostid decrypt --source <ENCRYPTED> --target <OUTPUT>
```

**Options:**

| Flag | Description |
|---|---|
| `-s, --source <PATH>` | Path to the encrypted directory (required) |
| `-t, --target <PATH>` | Path for the decrypted output (required) |
| `-p, --passphrase <TEXT>` | Passphrase (omit to be prompted) |

This is your escape hatch. No lock-in — standard crypto, open format. You can always get your files back.

---

### `ghostid unlock`

Decrypt an encrypted directory to a temporary workspace for a working session.

```
ghostid unlock --dir <ENCRYPTED>
```

Outputs the path to the temporary workspace. Work with your files normally, then lock when done.

**Options:**

| Flag | Description |
|---|---|
| `-d, --dir <PATH>` | Path to the encrypted directory (required) |
| `-p, --passphrase <TEXT>` | Passphrase (omit to be prompted) |

**Example:**

```
$ ghostid unlock --dir ~/my-encrypted-folder
Passphrase: ********
Unlocked. Workspace at: /tmp/ghostid-unlocked-a8f3e2
Run `ghostid lock` when done to re-encrypt.
```

---

### `ghostid lock`

Re-encrypt a temporary workspace and securely wipe the plaintext.

```
ghostid lock --workspace <TEMP_PATH> --dir <ENCRYPTED>
```

**Options:**

| Flag | Description |
|---|---|
| `-w, --workspace <PATH>` | Path to the unlocked temporary workspace (required) |
| `-d, --dir <PATH>` | Path to the encrypted directory to update (required) |
| `-p, --passphrase <TEXT>` | Passphrase (omit to be prompted) |

**Example:**

```
$ ghostid lock --workspace /tmp/ghostid-unlocked-a8f3e2 --dir ~/my-encrypted-folder
Passphrase: ********
Workspace wiped.
```

---

## Typical Workflows

### One-time encryption

Encrypt a folder and keep the encrypted version:

```
ghostid encrypt --source ~/Documents/private --target ~/Documents/private-encrypted
```

Verify it worked:

```
ghostid decrypt --source ~/Documents/private-encrypted --target /tmp/verify
diff -r ~/Documents/private /tmp/verify
rm -rf /tmp/verify
```

Then remove the original when you're confident.

### In-place encryption

Encrypt a folder where it stands — verification is automatic:

```
ghostid encrypt --source ~/Documents/private --in-place
```

Your folder is now `.ghost` blobs. Decrypt to get it back.

### Working session (unlock/lock)

For folders you need to work in regularly:

```
# Start working
ghostid unlock --dir ~/Documents/private
# → Workspace at: /tmp/ghostid-unlocked-a8f3e2

# ... edit files normally ...

# Done — re-encrypt and wipe
ghostid lock --workspace /tmp/ghostid-unlocked-a8f3e2 --dir ~/Documents/private
```

### Full export

Get everything back permanently:

```
ghostid decrypt --source ~/Documents/private --target ~/Documents/private-decrypted
```

---

## What's On Disk After Encryption

**Before:**

```
my-folder/
  Projects/TestProject.md
  Sessions/2026-04-06-session.md
  System/VaultIdentity.md
```

**After:**

```
my-folder/
  ab794136e771aa8ad188e8456f4b4040.ghost
  c3f8a21d9e4b7710adf2e6c845901bce.ghost
  f19e4a827c3d6b0195ea8d42f7c130ab.ghost
  .ghost-manifest
  .ghost-salt
```

No filenames. No folder structure. No readable content. Only `GHST` magic bytes identify these as GhostID files.

---

## Crypto Stack

| Layer | What | Why |
|---|---|---|
| **Encryption** | XChaCha20-Poly1305 | Authenticated encryption with 24-byte nonce — no nonce reuse risk |
| **Key derivation** | Argon2id (64MB memory, 3 iterations) | Memory-hard — resistant to GPU/ASIC brute-force attacks |
| **Filename obfuscation** | SHA-256(path + salt) | No folder structure or filename leakage |
| **Manifest** | Encrypted JSON blob | Maps opaque names back to original paths — itself encrypted |
| **Key handling** | Zeroized after use | Key material wiped from memory when no longer needed |

---

## File Format (.ghost)

Each `.ghost` file has a 62-byte header followed by the encrypted payload:

```
Offset  Size    Field
0       4       Magic bytes: "GHST"
4       2       Format version: 1 (u16 LE)
6       32      Salt (for Argon2id key derivation)
38      24      Nonce (unique per file, for XChaCha20-Poly1305)
62      N       Encrypted payload (ciphertext + 16-byte auth tag)
```

The format is open. Anyone can build a decryptor with the spec and the passphrase.

---

## Metadata Files

| File | Purpose | Encrypted? |
|---|---|---|
| `.ghost-manifest` | Maps opaque filenames to original paths | Yes (same format as `.ghost`) |
| `.ghost-salt` | Hex-encoded 32-byte salt for key derivation | No (needed to derive the key) |

---

## Threat Model

GhostID protects against:

| Threat | Description |
|---|---|
| **Device theft/loss** | Someone gets the machine, browses the drive |
| **Cloud sync exposure** | iCloud, Dropbox, Google Drive can read plaintext |
| **Unauthorized local access** | Other users, malware, forensic recovery |
| **Legal compulsion** | Can't hand over what you can't decrypt |

**Out of scope:** Content in memory during an unlocked session, screen capture, a compromised binary, or the user choosing to share.

**Key loss is permanent.** There is no backdoor. There is no recovery. There is no server. You own the key. You own the risk.

---

## Passphrase Guidance

- Minimum 12 characters (enforced — encryption will refuse anything shorter)
- A memorable sentence is better than a complex string: `the cat sat on my keyboard at 3am` beats `xK9#mP2!`
- The passphrase is set once at encryption time
- Rekey command (change passphrase) is planned but not yet built
- Never pass `-p` in scripts or shared terminals — use the interactive prompt

---

## Limitations (v0.1.0)

- **No incremental writes** — locking re-encrypts the entire folder, not just changed files
- **No rekey** — can't change the passphrase without a full decrypt/re-encrypt cycle
- **No progress bar** — large folders show file-by-file output but no percentage
- **Passphrase input is visible** — the prompt doesn't mask input (terminal limitation in current implementation)

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Error (wrong passphrase, missing files, invalid arguments, etc.) |

---

## Building From Source

**Requirements:** Rust toolchain (rustup.rs)

```
git clone <repo>
cd ghostid-cli
cargo build --release
cargo test
```

Tests use shipped encrypted test data — no plaintext in the repo. The repo practices what it preaches.
