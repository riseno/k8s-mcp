//! JSON Lines audit log of every tool call (PROPOSAL §12.5). Records are written by a
//! dedicated thread so tool calls never block on disk I/O.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;

use serde::Serialize;
use serde_json::Value;

use crate::cluster::home_dir;
use crate::error::{Error, Result};

/// Rotate the file when it would exceed this size.
const MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Rotated files kept (`audit.jsonl.1` … `.5`).
const KEEP: u32 = 5;

/// One audit record.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    /// RFC 3339 timestamp.
    pub ts: String,
    /// Random id of this server process.
    pub session: String,
    /// MCP client name/version, if known.
    pub client: Option<String>,
    /// Tool name.
    pub tool: String,
    /// Tool tier.
    pub tier: &'static str,
    /// Context used.
    pub context: Option<String>,
    /// Namespace argument, if any.
    pub namespace: Option<String>,
    /// Redacted arguments.
    pub args: Value,
    /// `ok` or `error`.
    pub result: &'static str,
    /// Error message (redacted) when `result` is `error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Number of findings returned.
    pub findings: usize,
    /// Response size in bytes.
    pub bytes: usize,
    /// Whether output was truncated.
    pub truncated: bool,
    /// Wall time.
    pub duration_ms: u64,
    /// Dry-run flag of write tools (always null in v0.1).
    pub dry_run: Option<bool>,
    /// Server version.
    pub server_version: &'static str,
}

type Sink = Box<dyn FnMut(&str) + Send>;

/// Where audit records go.
pub struct Audit {
    tx: Mutex<Option<Sender<String>>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Human description of the sink (for `doctor` and the policy resource).
    pub target: String,
}

impl Audit {
    /// Open an audit sink: `off`, `stderr`, or a file path. Files get mode 0600.
    pub fn open(target: &str) -> Result<Self> {
        let sink: Option<Sink> = match target {
            "off" => {
                tracing::warn!("audit log is off (--audit-log off): tool calls are not recorded");
                None
            }
            "stderr" => Some(Box::new(|line: &str| {
                let _ = writeln!(std::io::stderr(), "{line}");
            })),
            path => {
                let mut file = RotatingFile::open(PathBuf::from(path))?;
                Some(Box::new(move |line: &str| {
                    if let Err(e) = file.write_line(line) {
                        tracing::error!(error = %e, "cannot write audit log");
                    }
                }))
            }
        };
        let (tx, worker) = match sink {
            None => (None, None),
            Some(mut sink) => {
                let (tx, rx) = channel::<String>();
                let worker = std::thread::spawn(move || {
                    for line in rx {
                        sink(&line);
                    }
                });
                (Some(tx), Some(worker))
            }
        };
        Ok(Self {
            tx: Mutex::new(tx),
            worker: Mutex::new(worker),
            target: target.to_owned(),
        })
    }

    /// Queue a record.
    pub fn record(&self, rec: &Record) {
        let Ok(line) = serde_json::to_string(rec) else {
            return;
        };
        if let Some(tx) = self
            .tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = tx.send(line);
        }
    }

    /// Flush pending records and stop the writer.
    pub fn close(&self) {
        self.tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(w) = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = w.join();
        }
    }
}

impl Drop for Audit {
    fn drop(&mut self) {
        self.close();
    }
}

/// The default audit path: `$XDG_STATE_HOME/k8s-mcp/audit.jsonl`
/// (`~/Library/Application Support/k8s-mcp/` on macOS, `%LOCALAPPDATA%` on Windows).
pub fn default_path() -> Option<PathBuf> {
    let base = if cfg!(target_os = "macos") {
        home_dir().map(|h| h.join("Library/Application Support"))
    } else if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| home_dir().map(|h| h.join(".local/state")))
    };
    base.map(|b| b.join("k8s-mcp").join("audit.jsonl"))
}

/// A random session id (no extra dependencies: std's per-process random hasher keys).
pub fn session_id() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default(),
    );
    h.write_u32(std::process::id());
    format!("{:016x}", h.finish())
}

struct RotatingFile {
    path: PathBuf,
    file: File,
    size: u64,
}

impl RotatingFile {
    fn open(path: PathBuf) -> Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| io_err(&path, &e))?;
        }
        let file = open_append(&path)?;
        let size = file.metadata().map_or(0, |m| m.len());
        Ok(Self { path, file, size })
    }

    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let n = line.len() as u64 + 1;
        if self.size > 0 && self.size + n > MAX_BYTES {
            self.rotate()?;
        }
        writeln!(self.file, "{line}")?;
        self.size += n;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let numbered = |i: u32| {
            let mut s = self.path.clone().into_os_string();
            s.push(format!(".{i}"));
            PathBuf::from(s)
        };
        let _ = std::fs::remove_file(numbered(KEEP));
        for i in (1..KEEP).rev() {
            let _ = std::fs::rename(numbered(i), numbered(i + 1));
        }
        std::fs::rename(&self.path, numbered(1))?;
        self.file = open_append(&self.path).map_err(std::io::Error::other)?;
        self.size = 0;
        Ok(())
    }
}

fn open_append(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).map_err(|e| io_err(path, &e))
}

fn io_err(path: &Path, e: &std::io::Error) -> Error {
    Error::Config(format!(
        "cannot open audit log {}: {e}. Pass --audit-log <writable path>, --audit-log stderr, or --audit-log off.",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(tool: &str) -> Record {
        Record {
            ts: "2026-11-14T12:00:00Z".into(),
            session: "s".into(),
            client: None,
            tool: tool.into(),
            tier: "read",
            context: Some("dev".into()),
            namespace: None,
            args: serde_json::json!({}),
            result: "ok",
            error: None,
            findings: 0,
            bytes: 10,
            truncated: false,
            duration_ms: 1,
            dry_run: None,
            server_version: "0.1.0",
        }
    }

    #[test]
    fn writes_jsonl_with_private_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/audit.jsonl");
        let audit = Audit::open(path.to_str().unwrap()).unwrap();
        audit.record(&rec("list_contexts"));
        audit.record(&rec("get_logs"));
        audit.close();
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["tool"], "get_logs");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn rotates_and_keeps_five() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut f = RotatingFile::open(path.clone()).unwrap();
        f.size = MAX_BYTES; // pretend full
        for _ in 0..7 {
            f.write_line("{}").unwrap();
            f.size = MAX_BYTES;
        }
        assert!(path.exists());
        assert!(dir.path().join("audit.jsonl.5").exists());
        assert!(!dir.path().join("audit.jsonl.6").exists());
    }

    #[test]
    fn session_ids_differ() {
        assert_ne!(session_id(), session_id());
    }
}
