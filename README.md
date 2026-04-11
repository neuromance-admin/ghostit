# GhostIT

Garble your AI's markdown files — and let it keep reading them. Plus full folder encryption, CLI-first.

---

## What is GhostIT?

GhostIT turns any folder into an unreadable collection of encrypted blobs. No filenames. No folder structure. No readable content. Just binary noise and a passphrase that only you know.

If you lose the passphrase, the data is gone. There is no recovery, no backdoor, no server to contact. That's the design.

GhostIT is also an encryption protocol. AI coding assistants like Claude Code can work inside encrypted folders through GhostIT — reading, writing, and managing files without ever decrypting them to disk. The folder stays encrypted at all times, even during an active session.

---

## Install

**Homebrew (macOS / Linux):**

```
brew install neuromance-admin/tap/ghostit
```

**Manual download:**

Grab the binary for your platform from [Releases](https://github.com/neuromance-admin/ghostit/releases), extract it, and move it to your PATH:

```
tar xzf ghostit-macos-arm.tar.gz
sudo mv ghostit /usr/local/bin/
```

**Build from source:**

```
git clone https://github.com/neuromance-admin/ghostit.git
cd ghostit
cargo install --path .
```

`cargo install` copies the binary to `~/.cargo/bin/`, which is already on your PATH if you've installed Rust via `rustup`. Don't symlink from the cargo target directory — if you later move or clean the repo, the symlink will break.

Verify: `ghostit --version`

---

## Quick Start

**Encrypt a folder:**

```
ghostit on --source ~/my-folder --in-place
```

You'll be prompted for a passphrase (minimum 12 characters) and asked to confirm it. The folder is now encrypted.

**Decrypt it back:**

```
ghostit off --source ~/my-folder --in-place
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

GhostIT has three layers: **folder-level** operations, **file-level** protocol commands, and an **MCP server** for native AI integration.

### Folder-Level Commands

#### `ghostit on`

Encrypt a folder.

```
# To a separate location
ghostit on --source <FOLDER> --target <OUTPUT>

# In place — replaces the original
ghostit on --source <FOLDER> --in-place
```

In-place mode is safe. GhostIT encrypts to a staging area, decrypts it back, compares every file byte-for-byte against the original, and only replaces the folder if verification passes. If anything fails, your original is untouched.

Encrypting automatically creates a `CLAUDE.md` with protocol instructions for AI assistants.

#### `ghostit off`

Decrypt an encrypted folder.

```
# To a separate location
ghostit off --source <ENCRYPTED> --target <OUTPUT>

# In place — replaces the blobs with your original files
ghostit off --source <ENCRYPTED> --in-place
```

Same round-trip verification as encrypt. Your escape hatch — no lock-in, open format. Decrypting in place automatically removes the GhostIT `CLAUDE.md`.

#### `ghostit unlock`

Decrypt to a temporary workspace for a working session.

```
ghostit unlock --dir <ENCRYPTED>
# Unlocked. Workspace at: /tmp/ghostit-unlocked-a8f3e2
```

#### `ghostit lock`

Re-encrypt a workspace and wipe the plaintext.

```
ghostit lock --workspace /tmp/ghostit-unlocked-a8f3e2 --dir <ENCRYPTED>
# Workspace wiped.
```

---

### File-Level Protocol Commands

These commands operate on individual files inside an encrypted folder. The folder stays encrypted on disk at all times — plaintext never touches the filesystem.

#### `ghostit list`

List all files in an encrypted folder. Decrypts only the manifest.

```
$ ghostit list --dir ~/my-encrypted-folder
Projects/ClientPitch.md
Notes/meeting-notes.md
Contracts/nda-draft.md
```

#### `ghostit read`

Read a single file from an encrypted folder. Decrypts in memory, outputs to stdout. Nothing written to disk.

```
$ ghostit read --dir ~/my-encrypted-folder --file "Notes/meeting-notes.md"
---
title: Meeting Notes
---

# Meeting Notes

Discussed encryption protocol...
```

#### `ghostit write`

Write a file into an encrypted folder. Reads content from stdin, encrypts it, writes the blob. If the file is new, the manifest is updated. Plaintext never exists as a file.

```
echo "# New Note" | ghostit write --dir ~/my-encrypted-folder --file "Notes/new-note.md"
```

#### `ghostit remove`

Remove a file from an encrypted folder. Deletes the blob and updates the manifest.

```
ghostit remove --dir ~/my-encrypted-folder --file "Notes/old-note.md"
```

---

### MCP Server

GhostIT ships as an MCP (Model Context Protocol) server for native integration with AI coding assistants like Claude Code and Claude Desktop.

#### `ghostit serve`

Start the MCP server for an encrypted directory.

```
ghostit serve --dir <ENCRYPTED>
Passphrase: ********
GhostIT MCP server running.
```

The server prompts for the passphrase once at startup, holds it in memory, and exposes four MCP tools:

| Tool | Description |
|---|---|
| `ghostit_list` | List all files in the vault |
| `ghostit_read` | Read a file — decrypted in memory, never written to disk |
| `ghostit_write` | Write a file — encrypted before hitting disk |
| `ghostit_remove` | Remove a file and update the manifest |

The AI uses these as native tools. The passphrase never appears in the conversation. The vault stays encrypted on disk the entire time.

#### Claude Code Setup

Add this to your Claude Code MCP settings (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "ghostit": {
      "command": "ghostit",
      "args": ["serve", "--dir", "/absolute/path/to/encrypted/folder"]
    }
  }
}
```

That's it. Claude Code launches the GhostIT server, prompts for your passphrase, and works inside the encrypted folder natively. No `CLAUDE.md` instructions needed — the MCP tools handle everything.

---

### Why This Matters

With folder-level commands, you have to decrypt everything to work and re-encrypt when you're done. There's a window where your data is exposed.

With file-level commands and the MCP server, that window is zero. The folder on disk is always encrypted. You list, read, write, and remove files through the protocol — plaintext only ever exists in memory, in the moment you need it.

No other encryption tool provides this. GhostIT is the first encryption protocol that AI can run inside.

---

All commands prompt for the passphrase interactively. Pass `-p` to provide it directly (not recommended — stays in shell history).

---

## How It Works

GhostIT has three layers:

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

**GhostIT protects against:**

| Threat | How |
|---|---|
| Device theft or loss | Files are encrypted at rest — browsing the drive reveals nothing |
| Cloud sync exposure | iCloud, Dropbox, Google Drive only ever see `.ghost` blobs |
| Unauthorized local access | Other users, malware, forensic recovery — all see binary noise |
| Legal compulsion | Can't hand over what you can't decrypt |

**GhostIT does not protect against:**

- Content in memory during an active session
- Screen capture or shoulder surfing
- A compromised GhostIT binary
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

GhostIT integrates with [Claude Code](https://claude.ai/code) in two ways:

### Automatic (CLAUDE.md)

When you encrypt a folder, GhostIT automatically creates a `CLAUDE.md` file with protocol instructions. When Claude Code opens that directory, it detects the encrypted vault, asks for your passphrase, and uses `ghostit` CLI commands for all file operations. Zero setup. The AI is instructed to always ask the user to confirm their passphrase before any encrypt operation — it will never encrypt on a single entry.

When you decrypt the folder, the `CLAUDE.md` is automatically removed.

### Native (MCP Server)

For a deeper integration, run GhostIT as an MCP server. The AI gets native tools instead of CLI commands, and the passphrase stays in the server process — never in the conversation.

```json
{
  "mcpServers": {
    "ghostit": {
      "command": "ghostit",
      "args": ["serve", "--dir", "/path/to/encrypted/folder"]
    }
  }
}
```

Both approaches keep the folder encrypted on disk at all times. The MCP server is recommended for regular use — it's cleaner and more secure.

---

## Product Architecture

GhostIT is designed to work at multiple levels:

**As a CLI tool** — encrypt any folder, decrypt it back. Simple, standalone, no dependencies.

**As a file-level protocol** — list, read, write, and remove individual files inside an encrypted folder without ever decrypting it to disk. The folder stays encrypted at all times.

**As an MCP server** — native integration with AI coding assistants. The AI uses encryption-aware tools directly. Passphrase never enters the conversation.

**As a Claude Code encryption layer** — encrypt a folder and keep working in it through Claude Code. GhostIT auto-generates the integration config. Zero setup, zero plaintext on disk.

**As a Rust library** — GhostIT exposes its crypto primitives as a crate. Other applications can import it directly for file-level encryption and decryption without shelling out to the CLI.

---

## Current Limitations

- **No incremental writes** — locking re-encrypts the entire folder, not just changed files
- **No rekey** — changing the passphrase requires a full decrypt/re-encrypt cycle
- **No passphrase masking** — input is visible in the terminal

---

## Uninstall

**Homebrew:**

```
brew uninstall ghostit
brew untap neuromance-admin/tap
```

**Built from source (via `cargo install`):**

```
cargo uninstall ghostit
```

**Manual binary install (if you copied to `/usr/local/bin`):**

```
sudo rm /usr/local/bin/ghostit
```

No config files, no daemon, no account — just the binary. Your encrypted folders remain intact but will need GhostIT (or a compatible decryptor) to unlock.

---

## License

Apache 2.0

---

Built by [neuromance](https://www.neuromance.co.za).
