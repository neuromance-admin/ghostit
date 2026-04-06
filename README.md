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

GhostID has two layers of commands: **folder-level** operations for encrypting and decrypting entire directories, and **file-level** operations for working inside an encrypted folder without ever decrypting it to disk.

### Folder-Level Commands

#### `ghostid encrypt`

Encrypt a folder.

```
# To a separate location
ghostid encrypt --source <FOLDER> --target <OUTPUT>

# In place — replaces the original
ghostid encrypt --source <FOLDER> --in-place
```

In-place mode is safe. GhostID encrypts to a staging area, decrypts it back, compares every file byte-for-byte against the original, and only replaces the folder if verification passes. If anything fails, your original is untouched.

#### `ghostid decrypt`

Decrypt an encrypted folder.

```
# To a separate location
ghostid decrypt --source <ENCRYPTED> --target <OUTPUT>

# In place — replaces the blobs with your original files
ghostid decrypt --source <ENCRYPTED> --in-place
```

Same round-trip verification as encrypt. Your escape hatch — no lock-in, open format.

#### `ghostid unlock`

Decrypt to a temporary workspace for a working session.

```
ghostid unlock --dir <ENCRYPTED>
# Unlocked. Workspace at: /tmp/ghostid-unlocked-a8f3e2
```

#### `ghostid lock`

Re-encrypt a workspace and wipe the plaintext.

```
ghostid lock --workspace /tmp/ghostid-unlocked-a8f3e2 --dir <ENCRYPTED>
# Workspace wiped.
```

---

### File-Level Protocol Commands

These commands operate on individual files inside an encrypted folder. The folder stays encrypted on disk at all times — plaintext never touches the filesystem.

#### `ghostid list`

List all files in an encrypted folder. Decrypts only the manifest.

```
$ ghostid list --dir ~/my-encrypted-folder
Projects/ClientPitch.md
Notes/meeting-notes.md
Contracts/nda-draft.md
```

#### `ghostid read`

Read a single file from an encrypted folder. Decrypts in memory, outputs to stdout. Nothing written to disk.

```
$ ghostid read --dir ~/my-encrypted-folder --file "Notes/meeting-notes.md"
---
title: Meeting Notes
---

# Meeting Notes

Discussed encryption protocol...
```

#### `ghostid write`

Write a file into an encrypted folder. Reads content from stdin, encrypts it, writes the blob. If the file is new, the manifest is updated. Plaintext never exists as a file.

```
echo "# New Note" | ghostid write --dir ~/my-encrypted-folder --file "Notes/new-note.md"
```

#### `ghostid remove`

Remove a file from an encrypted folder. Deletes the blob and updates the manifest.

```
ghostid remove --dir ~/my-encrypted-folder --file "Notes/old-note.md"
```

---

### Why This Matters

With folder-level commands, you have to decrypt everything to work and re-encrypt when you're done. There's a window where your data is exposed.

With file-level commands, that window is zero. The folder on disk is always encrypted. You list, read, write, and remove files through the protocol — plaintext only ever exists in memory, in the moment you need it.

This is what makes GhostID an encryption protocol, not just an encryption tool.

---

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

**As a CLI tool** — encrypt any folder, decrypt it back. Simple, standalone, no dependencies.

**As a file-level protocol** — list, read, write, and remove individual files inside an encrypted folder without ever decrypting it to disk. The folder stays encrypted at all times. Plaintext only exists in memory, in the moment you need it.

**As a Rust library** — GhostID exposes its crypto primitives as a crate. Other applications can import it directly for file-level encryption and decryption without shelling out to the CLI.

---

## Current Limitations

- **No incremental writes** — locking re-encrypts the entire folder, not just changed files
- **No rekey** — changing the passphrase requires a full decrypt/re-encrypt cycle
- **No passphrase masking** — input is visible in the terminal

---

## License

Apache 2.0

---

Built by [neuromance](https://www.neuromance.co.za).
