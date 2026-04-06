# GhostID

Encrypt any folder on your drive. No account. No server. Your key, your data.

---

## What is GhostID?

GhostID turns any folder into an unreadable collection of encrypted blobs. No filenames. No folder structure. No readable content. Just binary noise and a passphrase that only you know.

If you lose the passphrase, the data is gone. There is no recovery, no backdoor, no server to contact. That's the design.

GhostID is also an encryption protocol. AI coding assistants like Claude Code can work inside encrypted folders through GhostID — reading, writing, and managing files without ever decrypting them to disk. The folder stays encrypted at all times, even during an active session.

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
  CLAUDE.md
```

No filenames. No folder structure. No way to tell what's inside or how many files there are. `CLAUDE.md` is the only plaintext file — it contains protocol instructions for AI assistants, not your data.

---

## Commands

GhostID has three layers: **folder-level** operations, **file-level** protocol commands, and an **MCP server** for native AI integration.

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

Encrypting automatically creates a `CLAUDE.md` with protocol instructions for AI assistants.

#### `ghostid decrypt`

Decrypt an encrypted folder.

```
# To a separate location
ghostid decrypt --source <ENCRYPTED> --target <OUTPUT>

# In place — replaces the blobs with your original files
ghostid decrypt --source <ENCRYPTED> --in-place
```

Same round-trip verification as encrypt. Your escape hatch — no lock-in, open format. Decrypting in place automatically removes the GhostID `CLAUDE.md`.

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

### MCP Server

GhostID ships as an MCP (Model Context Protocol) server for native integration with AI coding assistants like Claude Code and Claude Desktop.

#### `ghostid serve`

Start the MCP server for an encrypted directory.

```
ghostid serve --dir <ENCRYPTED>
Passphrase: ********
GhostID MCP server running.
```

The server prompts for the passphrase once at startup, holds it in memory, and exposes four MCP tools:

| Tool | Description |
|---|---|
| `ghostid_list` | List all files in the vault |
| `ghostid_read` | Read a file — decrypted in memory, never written to disk |
| `ghostid_write` | Write a file — encrypted before hitting disk |
| `ghostid_remove` | Remove a file and update the manifest |

The AI uses these as native tools. The passphrase never appears in the conversation. The vault stays encrypted on disk the entire time.

#### Claude Code Setup

Add this to your Claude Code MCP settings (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "ghostid": {
      "command": "ghostid",
      "args": ["serve", "--dir", "/absolute/path/to/encrypted/folder"]
    }
  }
}
```

That's it. Claude Code launches the GhostID server, prompts for your passphrase, and works inside the encrypted folder natively. No `CLAUDE.md` instructions needed — the MCP tools handle everything.

---

### Why This Matters

With folder-level commands, you have to decrypt everything to work and re-encrypt when you're done. There's a window where your data is exposed.

With file-level commands and the MCP server, that window is zero. The folder on disk is always encrypted. You list, read, write, and remove files through the protocol — plaintext only ever exists in memory, in the moment you need it.

No other encryption tool provides this. GhostID is the first encryption protocol that AI can run inside.

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
| `CLAUDE.md` | Protocol instructions for AI assistants | No (contains no user data) |

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

## Claude Code Integration

GhostID integrates with [Claude Code](https://claude.ai/code) in two ways:

### Automatic (CLAUDE.md)

When you encrypt a folder, GhostID automatically creates a `CLAUDE.md` file with protocol instructions. When Claude Code opens that directory, it detects the encrypted vault, asks for your passphrase, and uses `ghostid` CLI commands for all file operations. Zero setup.

When you decrypt the folder, the `CLAUDE.md` is automatically removed.

### Native (MCP Server)

For a deeper integration, run GhostID as an MCP server. The AI gets native tools instead of CLI commands, and the passphrase stays in the server process — never in the conversation.

```json
{
  "mcpServers": {
    "ghostid": {
      "command": "ghostid",
      "args": ["serve", "--dir", "/path/to/encrypted/folder"]
    }
  }
}
```

Both approaches keep the folder encrypted on disk at all times. The MCP server is recommended for regular use — it's cleaner and more secure.

---

## Product Architecture

GhostID is designed to work at multiple levels:

**As a CLI tool** — encrypt any folder, decrypt it back. Simple, standalone, no dependencies.

**As a file-level protocol** — list, read, write, and remove individual files inside an encrypted folder without ever decrypting it to disk. The folder stays encrypted at all times.

**As an MCP server** — native integration with AI coding assistants. The AI uses encryption-aware tools directly. Passphrase never enters the conversation.

**As a Claude Code encryption layer** — encrypt a folder and keep working in it through Claude Code. GhostID auto-generates the integration config. Zero setup, zero plaintext on disk.

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
