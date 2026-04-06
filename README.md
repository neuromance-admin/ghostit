# GhostID

Encrypt any folder on your drive. No account. No server. Your key, your data.

---

## What is GhostID?

GhostID turns any folder into an unreadable collection of encrypted blobs. No filenames. No folder structure. No readable content. Just binary noise and a passphrase that only you know.

If you lose the passphrase, the data is gone. There is no recovery, no backdoor, no server to contact. That's the design.

---

## Install

**Homebrew (macOS / Linux):**

```
brew tap neuromance-admin/tap
brew install ghostid
```

**Manual download:**

Grab the binary for your platform from [Releases](https://github.com/neuromance-admin/ghostid/releases), extract it, and move it to your PATH:

```
tar xzf ghostid-macos-arm.tar.gz
sudo mv ghostid /usr/local/bin/
```

**Build from source:**

```
git clone https://github.com/neuromance-admin/ghostid.git
cd ghostid
cargo build --release
sudo ln -sf target/release/ghostid /usr/local/bin/ghostid
```

Verify: `ghostid --version`

---

## Quick Start

**Encrypt a folder:**

```
ghostid encrypt --source ~/my-folder --in-place
```

You'll be prompted for a passphrase (minimum 12 characters) and asked to confirm it. The folder is now encrypted.

**Decrypt it back:**

```
ghostid decrypt --source ~/my-folder --in-place
```

Same passphrase. Your files are back.

---

## What It Looks Like

**Before — readable by anyone:**

```
my-folder/
  Projects/ClientPitch.md
  Notes/meeting-notes.md
  Contracts/nda-draft.md
```

**After — useless without the passphrase:**

```
my-folder/
  ab794136e771aa8ad188e8456f4b4040.ghost
  c3f8a21d9e4b7710adf2e6c845901bce.ghost
  f19e4a827c3d6b0195ea8d42f7c130ab.ghost
  .ghost-manifest
  .ghost-salt
```

No filenames. No folder structure. No way to tell what's inside or how many files there are.

---

## Commands

### `ghostid encrypt`

Encrypt a folder.

```
# To a separate location
ghostid encrypt --source <FOLDER> --target <OUTPUT>

# In place — replaces the original
ghostid encrypt --source <FOLDER> --in-place
```

In-place mode is safe. GhostID encrypts to a staging area, decrypts it back, compares every file byte-for-byte against the original, and only replaces the folder if verification passes. If anything fails, your original is untouched.

### `ghostid decrypt`

Decrypt an encrypted folder.

```
# To a separate location
ghostid decrypt --source <ENCRYPTED> --target <OUTPUT>

# In place — replaces the blobs with your original files
ghostid decrypt --source <ENCRYPTED> --in-place
```

Same round-trip verification as encrypt. Your escape hatch — no lock-in, open format.

### `ghostid unlock`

Decrypt to a temporary workspace for a working session.

```
ghostid unlock --dir <ENCRYPTED>
# Unlocked. Workspace at: /tmp/ghostid-unlocked-a8f3e2
```

### `ghostid lock`

Re-encrypt a workspace and wipe the plaintext.

```
ghostid lock --workspace /tmp/ghostid-unlocked-a8f3e2 --dir <ENCRYPTED>
# Workspace wiped.
```

All commands prompt for the passphrase interactively. Pass `-p` to provide it directly (not recommended — stays in shell history).

---

## How It Works

GhostID has three layers:

### Layer 1 — Encryption

Every file is individually encrypted using **XChaCha20-Poly1305**, an authenticated cipher. This means your data is both unreadable and tamper-proof — if someone modifies even one byte of an encrypted file, decryption will refuse to proceed.

### Layer 2 — Key Derivation

Your passphrase is turned into a 256-bit encryption key using **Argon2id**, the winner of the Password Hashing Competition. It's memory-hard — it deliberately uses 64MB of RAM per attempt, which makes brute-force attacks with GPUs or custom hardware impractical.

### Layer 3 — Structure Obfuscation

Filenames and folder structure are hashed using **SHA-256** with a random salt. An attacker can't tell what your files are called, how they're organised, or how many there are. The mapping between hashed names and original paths is stored in an encrypted manifest — itself a `.ghost` file.

---

## File Format

Each `.ghost` file is a self-contained encrypted document:

```
Offset  Size    Field
0       4       Magic bytes: "GHST"
4       2       Format version (u16 LE, currently 1)
6       32      Salt (Argon2id key derivation)
38      24      Nonce (unique per file)
62      N       Encrypted payload + 16-byte auth tag
```

The format is open. The crypto is standard. Anyone can build a compatible decryptor with the spec above and a passphrase. No proprietary lock-in.

**Metadata files:**

| File | Purpose | Encrypted? |
|---|---|---|
| `.ghost-manifest` | Maps hashed filenames to original paths | Yes |
| `.ghost-salt` | Salt for key derivation | No (required to derive the key) |

---

## Threat Model

**GhostID protects against:**

| Threat | How |
|---|---|
| Device theft or loss | Files are encrypted at rest — browsing the drive reveals nothing |
| Cloud sync exposure | iCloud, Dropbox, Google Drive only ever see `.ghost` blobs |
| Unauthorized local access | Other users, malware, forensic recovery — all see binary noise |
| Legal compulsion | Can't hand over what you can't decrypt |

**GhostID does not protect against:**

- Content in memory during an active session
- Screen capture or shoulder surfing
- A compromised GhostID binary
- You choosing to share the decrypted data
- Keyloggers or other malware on a compromised machine

**The weakest link is always the passphrase.** A 12-character minimum is enforced, but longer is stronger. A memorable sentence beats a complex string: `the cat sat on my keyboard at 3am` is better than `xK9#mP2!`.

---

## Passphrase Rules

- Minimum 12 characters — enforced at the crypto layer, no way to bypass it
- Set once at encryption time
- Encryption prompts twice for confirmation
- If you lose it, your data is permanently gone — by design
- Never pass `-p` in shared terminals or scripts — use the interactive prompt

---

## Product Architecture

GhostID is designed to work at multiple levels:

**As a CLI tool** — what you have now. Encrypt any folder, decrypt it back. Simple, standalone, no dependencies.

**As a Rust library** — GhostID exposes its crypto primitives as a crate. Other applications can import it directly for file-level encryption and decryption without shelling out to the CLI.

**As an encryption protocol** — the planned direction. Instead of encrypting and decrypting entire folders, GhostID operates as a transparent layer between an application and the filesystem. Files are encrypted on write and decrypted on read, in memory. Plaintext never touches the disk. The folder looks encrypted at all times, even during an active session.

---

## Current Limitations

- **No incremental writes** — locking re-encrypts the entire folder, not just changed files
- **No rekey** — changing the passphrase requires a full decrypt/re-encrypt cycle
- **No passphrase masking** — input is visible in the terminal
- **Whole-folder operations only** — file-level read/write protocol is planned but not yet built

---

## License

Apache 2.0

---

Built by [neuromance](https://www.neuromance.co.za).
