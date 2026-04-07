//! MCP (Model Context Protocol) server for GhostIT
//!
//! Exposes encrypted vault operations as MCP tools over stdio.
//! The passphrase is held in memory for the session — never transmitted over the protocol.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::vault;

/// Run the MCP server over stdio
pub fn run(dir: PathBuf, passphrase: String) -> Result<(), String> {
    // Verify the passphrase works by loading the manifest
    let _ = vault::list_files(&dir, &passphrase)?;
    eprintln!("GhostIT MCP server running. Vault: {}", dir.display());

    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("Failed to read stdin: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let response = handle_request(&request, &dir, &passphrase);

        if let Some(resp) = response {
            let mut out = stdout.lock();
            serde_json::to_writer(&mut out, &resp)
                .map_err(|e| format!("Failed to write response: {e}"))?;
            out.write_all(b"\n")
                .map_err(|e| format!("Failed to write newline: {e}"))?;
            out.flush()
                .map_err(|e| format!("Failed to flush stdout: {e}"))?;
        }
    }

    Ok(())
}

fn handle_request(request: &Value, dir: &Path, passphrase: &str) -> Option<Value> {
    let method = request.get("method")?.as_str()?;
    let id = request.get("id").cloned();

    match method {
        "initialize" => {
            Some(jsonrpc_response(id, json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "ghostit",
                    "version": "0.1.0"
                }
            })))
        }

        "notifications/initialized" => None,

        "tools/list" => {
            Some(jsonrpc_response(id, json!({
                "tools": [
                    {
                        "name": "ghostit_list",
                        "description": "List all files in the encrypted vault. Returns file paths sorted alphabetically.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                    },
                    {
                        "name": "ghostit_read",
                        "description": "Read a single file from the encrypted vault. Returns the decrypted content. The file is never written to disk as plaintext.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "description": "Relative path of the file to read (e.g. 'Sessions/2026-04-06.md')"
                                }
                            },
                            "required": ["file"]
                        }
                    },
                    {
                        "name": "ghostit_write",
                        "description": "Write a file to the encrypted vault. The content is encrypted before writing to disk. Plaintext never exists as a file. If the file is new, the manifest is updated.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "description": "Relative path for the file (e.g. 'Sessions/2026-04-06b.md')"
                                },
                                "content": {
                                    "type": "string",
                                    "description": "The content to write"
                                }
                            },
                            "required": ["file", "content"]
                        }
                    },
                    {
                        "name": "ghostit_remove",
                        "description": "Remove a file from the encrypted vault. Deletes the encrypted blob and updates the manifest.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "file": {
                                    "type": "string",
                                    "description": "Relative path of the file to remove"
                                }
                            },
                            "required": ["file"]
                        }
                    }
                ]
            })))
        }

        "tools/call" => {
            let params = request.get("params")?;
            let tool_name = params.get("name")?.as_str()?;
            let args = params.get("arguments").cloned().unwrap_or(json!({}));

            let result = handle_tool_call(tool_name, &args, dir, passphrase);

            match result {
                Ok(content) => {
                    Some(jsonrpc_response(id, json!({
                        "content": [
                            {
                                "type": "text",
                                "text": content
                            }
                        ]
                    })))
                }
                Err(e) => {
                    Some(jsonrpc_response(id, json!({
                        "content": [
                            {
                                "type": "text",
                                "text": e
                            }
                        ],
                        "isError": true
                    })))
                }
            }
        }

        _ => {
            Some(jsonrpc_error(id, -32601, "Method not found"))
        }
    }
}

fn handle_tool_call(
    tool_name: &str,
    args: &Value,
    dir: &Path,
    passphrase: &str,
) -> Result<String, String> {
    match tool_name {
        "ghostit_list" => {
            let files = vault::list_files(dir, passphrase)?;
            Ok(files.join("\n"))
        }

        "ghostit_read" => {
            let file = args.get("file")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'file' argument")?;
            let content = vault::read_file(dir, file, passphrase)?;
            String::from_utf8(content)
                .map_err(|_| "File contains non-UTF8 content".to_string())
        }

        "ghostit_write" => {
            let file = args.get("file")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'file' argument")?;
            let content = args.get("content")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'content' argument")?;
            vault::write_file(dir, file, content.as_bytes(), passphrase)?;
            Ok(format!("Written: {}", file))
        }

        "ghostit_remove" => {
            let file = args.get("file")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'file' argument")?;
            vault::remove_file(dir, file, passphrase)?;
            Ok(format!("Removed: {}", file))
        }

        _ => Err(format!("Unknown tool: {}", tool_name)),
    }
}

fn jsonrpc_response(id: Option<Value>, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "result": result
    })
}

fn jsonrpc_error(id: Option<Value>, code: i32, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message
        }
    })
}
