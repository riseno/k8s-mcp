//! `cargo xtask eval`: apply every scenario in `evals/scenarios/`, ask the stdio server to
//! diagnose each one over MCP, score the ranked finding ids and enforce the v0.1 gates.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{CONTEXT, kubeconfig, kubectl, output, root, run, verify_context};

const PROTOCOL_VERSION: &str = "2025-11-25";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    id: String,
    symptom: String,
    tool: String,
    args: Value,
    settle_seconds: u64,
    expected: Expected,
    #[serde(default)]
    forbidden: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    primary: String,
    #[serde(default)]
    acceptable: Vec<String>,
}

impl Scenario {
    fn namespace(&self) -> &str {
        self.args["namespace"].as_str().unwrap_or_default()
    }
}

#[derive(Debug, Default, PartialEq)]
struct Score {
    top1: bool,
    top3: bool,
    forbidden: bool,
}

/// Top-1: the primary id ranks first. Top-3: the primary or an acceptable id is in the
/// first three. Forbidden: any forbidden id appears anywhere.
fn score(s: &Scenario, ids: &[String]) -> Score {
    let expected = |id: &String| *id == s.expected.primary || s.expected.acceptable.contains(id);
    Score {
        top1: ids.first() == Some(&s.expected.primary),
        top3: ids.iter().take(3).any(expected),
        forbidden: ids.iter().any(|id| s.forbidden.contains(id)),
    }
}

/// A successful tool call: ranked finding ids, result size and call latency.
struct Response {
    ids: Vec<String>,
    bytes: usize,
    latency: Duration,
}

struct Outcome {
    dir: String,
    score: Score,
    response: Result<Response>,
}

#[derive(Debug, PartialEq)]
struct Summary {
    total: usize,
    top1: usize,
    top3: usize,
    forbidden: usize,
    median_bytes: usize,
    p95: Duration,
}

impl Summary {
    fn new(outcomes: &[Outcome]) -> Self {
        let count = |f: fn(&Score) -> bool| outcomes.iter().filter(|o| f(&o.score)).count();
        let ok: Vec<&Response> = outcomes
            .iter()
            .filter_map(|o| o.response.as_ref().ok())
            .collect();
        Self {
            total: outcomes.len(),
            top1: count(|s| s.top1),
            top3: count(|s| s.top3),
            forbidden: count(|s| s.forbidden),
            median_bytes: median(ok.iter().map(|r| r.bytes).collect()),
            p95: p95(ok.iter().map(|r| r.latency).collect()),
        }
    }

    /// v0.1 gates: top-1 >= 85%, top-3 = 100%, no forbidden findings.
    fn passes(&self) -> bool {
        self.total > 0
            && self.top1 * 100 >= self.total * 85
            && self.top3 == self.total
            && self.forbidden == 0
    }
}

fn median(mut v: Vec<usize>) -> usize {
    v.sort_unstable();
    match v.len() {
        0 => 0,
        n if n % 2 == 0 => (v[n / 2 - 1] + v[n / 2]) / 2,
        n => v[n / 2],
    }
}

/// Nearest-rank 95th percentile.
fn p95(mut v: Vec<Duration>) -> Duration {
    v.sort_unstable();
    match v.len() {
        0 => Duration::ZERO,
        n => v[(n * 95).div_ceil(100) - 1],
    }
}

pub fn main(args: &[String]) -> Result<()> {
    let (only, keep) = parse_args(args)?;
    let scenarios = load_scenarios(only.as_deref())?;
    verify_context()?;
    run(Command::new("cargo").args(["build", "-p", "k8s-mcp-server"]))?;
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root().join("target"), PathBuf::from);
    let bin = target.join("debug/k8s-mcp");

    let mut apply = kubectl();
    apply.arg("apply");
    for (dir, _) in &scenarios {
        apply
            .arg("-f")
            .arg(scenarios_dir().join(dir).join("manifest.yaml"));
    }
    run(&mut apply)?;
    let settle = scenarios
        .iter()
        .map(|(_, s)| s.settle_seconds)
        .max()
        .unwrap_or(0);
    println!(
        "waiting {settle}s for {} scenario(s) to settle",
        scenarios.len()
    );
    std::thread::sleep(Duration::from_secs(settle));

    let outcomes: Vec<Outcome> = scenarios
        .iter()
        .map(|(dir, s)| {
            println!("{dir}: {}", s.symptom);
            let response = call(&bin, s);
            let score = response
                .as_ref()
                .map(|r| score(s, &r.ids))
                .unwrap_or_default();
            Outcome {
                dir: dir.clone(),
                score,
                response,
            }
        })
        .collect();

    if !keep {
        let mut delete = kubectl();
        delete.args(["delete", "namespace", "--wait=false", "--ignore-not-found"]);
        delete.args(scenarios.iter().map(|(_, s)| s.namespace()));
        run(&mut delete)?;
    }

    let summary = Summary::new(&outcomes);
    let report = render(&scenarios, &outcomes, &summary)?;
    println!("{report}");
    if only.is_none() {
        let path = root().join(format!("evals/results/{}.md", env!("CARGO_PKG_VERSION")));
        std::fs::create_dir_all(root().join("evals/results"))?;
        std::fs::write(&path, &report)?;
        println!("wrote {}", path.display());
    }
    if !summary.passes() {
        bail!("eval gates failed: need top-1 >= 85%, top-3 = 100%, forbidden = 0");
    }
    Ok(())
}

fn parse_args(args: &[String]) -> Result<(Option<String>, bool)> {
    let (mut only, mut keep) = (None, false);
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--keep" => keep = true,
            "--scenario" => only = Some(it.next().context("--scenario needs an id")?.clone()),
            other => {
                bail!("unknown eval argument {other:?}; usage: eval [--scenario <id>] [--keep]")
            }
        }
    }
    Ok((only, keep))
}

fn scenarios_dir() -> PathBuf {
    root().join("evals/scenarios")
}

/// Every `evals/scenarios/<NN-id>/scenario.yaml`, sorted by directory, optionally filtered by
/// id or directory name.
fn load_scenarios(only: Option<&str>) -> Result<Vec<(String, Scenario)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(scenarios_dir())? {
        let dir = entry?.file_name().to_string_lossy().into_owned();
        let path = scenarios_dir().join(&dir).join("scenario.yaml");
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let s: Scenario =
            serde_saphyr::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        if !dir.ends_with(&format!("-{}", s.id)) || s.namespace() != format!("eval-{}", s.id) {
            bail!(
                "{}: directory must be <NN>-{id} and args.namespace eval-{id}",
                path.display(),
                id = s.id
            );
        }
        if only.is_none_or(|o| o == dir || o == s.id) {
            out.push((dir, s));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    if out.is_empty() {
        bail!("no scenario matches {only:?}");
    }
    Ok(out)
}

/// One server process per scenario: initialize, initialized, then the scenario's tool call.
fn call(bin: &Path, s: &Scenario) -> Result<Response> {
    let mut server = Server::spawn(bin)?;
    server.request(
        "initialize",
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "k8s-mcp-eval", "version": env!("CARGO_PKG_VERSION")},
        }),
    )?;
    server.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
    let start = Instant::now();
    let result = server.request("tools/call", json!({"name": s.tool, "arguments": s.args}))?;
    let latency = start.elapsed();
    if result["isError"] == true {
        bail!("{} returned an error: {}", s.tool, result["content"]);
    }
    let ids = result["structuredContent"]["findings"]
        .as_array()
        .context("result.structuredContent.findings is missing")?
        .iter()
        .filter_map(|f| f["id"].as_str().map(String::from))
        .collect();
    Ok(Response {
        ids,
        bytes: result.to_string().len(),
        latency,
    })
}

/// The server under test, speaking newline-delimited JSON-RPC over stdio.
struct Server {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
}

impl Server {
    fn spawn(bin: &Path) -> Result<Self> {
        let mut child = Command::new(bin)
            .arg("--kubeconfig")
            .arg(kubeconfig())
            .args(["--context", CONTEXT, "--audit-log", "off"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn {}", bin.display()))?;
        let stdin = child.stdin.take().context("server stdin")?;
        let stdout = child.stdout.take().context("server stdout")?;
        // A reader thread lets `request` time out instead of blocking on a hung server.
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
            next_id: 0,
        })
    }

    fn send(&mut self, msg: &Value) -> Result<()> {
        writeln!(self.stdin, "{msg}").context("write to server stdin")
    }

    /// Send a request and return its `result`, skipping notifications and other ids.
    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            let line = match self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => {
                    bail!("no response to {method} within {RESPONSE_TIMEOUT:?}")
                }
                Err(RecvTimeoutError::Disconnected) => {
                    bail!("server closed stdout before answering {method}; see its stderr above")
                }
            };
            let msg: Value = serde_json::from_str(&line)
                .with_context(|| format!("server wrote a non-JSON line to stdout: {line}"))?;
            if msg["id"] != id {
                continue;
            }
            if let Some(err) = msg.get("error") {
                bail!("{method} failed: {err}");
            }
            return msg.get("result").cloned().context("response has no result");
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn render(scenarios: &[(String, Scenario)], outcomes: &[Outcome], sum: &Summary) -> Result<String> {
    use std::fmt::Write as _;
    let k8s = output(kubectl().args([
        "get",
        "nodes",
        "-o",
        "jsonpath={.items[0].status.nodeInfo.kubeletVersion}",
    ]))?;
    let mark = |b: bool| if b { "yes" } else { "no" };
    let pct = |n: usize| 100.0 * n as f64 / sum.total as f64;
    let mut md = format!(
        "# Eval results: k8s-mcp {}\n\nKubernetes {k8s} on kind. Generated by `cargo xtask eval`.\n\n\
         | Scenario | Tool | Expected | Top findings | Top-1 | Top-3 | Forbidden | Bytes | ms |\n\
         |---|---|---|---|---|---|---|---|---|\n",
        env!("CARGO_PKG_VERSION")
    );
    for ((_, s), o) in scenarios.iter().zip(outcomes) {
        let (found, bytes, ms) = match &o.response {
            Ok(r) => (
                r.ids.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
                r.bytes.to_string(),
                r.latency.as_millis().to_string(),
            ),
            Err(e) => (
                format!("error: {e:#}").replace('|', "/"),
                "-".into(),
                "-".into(),
            ),
        };
        writeln!(
            md,
            "| {} | {} | {} | {found} | {} | {} | {} | {bytes} | {ms} |",
            o.dir,
            s.tool,
            s.expected.primary,
            mark(o.score.top1),
            mark(o.score.top3),
            mark(o.score.forbidden)
        )?;
    }
    writeln!(
        md,
        "\n- Top-1 accuracy: {}/{} ({:.1}%), gate >= 85%\n- Top-3 accuracy: {}/{} ({:.1}%), gate = 100%\n\
         - Forbidden-finding rate: {}/{} ({:.1}%), gate = 0\n- Median response bytes: {}\n- p95 latency: {} ms\n\
         - Gates: {}",
        sum.top1,
        sum.total,
        pct(sum.top1),
        sum.top3,
        sum.total,
        pct(sum.top3),
        sum.forbidden,
        sum.total,
        pct(sum.forbidden),
        sum.median_bytes,
        sum.p95.as_millis(),
        if sum.passes() { "PASS" } else { "FAIL" }
    )?;
    Ok(md)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario() -> Scenario {
        serde_saphyr::from_str(
            "id: x\nsymptom: s\ntool: diagnose_pod\nargs: {name: p, namespace: eval-x}\nsettle_seconds: 1\n\
             expected: {primary: a, acceptable: [b]}\nforbidden: [f]\n",
        )
        .unwrap()
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    fn outcome(score: Score, bytes: usize, ms: u64) -> Outcome {
        let response = Ok(Response {
            ids: vec![],
            bytes,
            latency: Duration::from_millis(ms),
        });
        Outcome {
            dir: String::new(),
            score,
            response,
        }
    }

    #[test]
    fn scoring() {
        let s = scenario();
        assert_eq!(
            score(&s, &ids(&["a"])),
            Score {
                top1: true,
                top3: true,
                forbidden: false
            }
        );
        assert_eq!(
            score(&s, &ids(&["c", "d", "b"])),
            Score {
                top1: false,
                top3: true,
                forbidden: false
            }
        );
        assert_eq!(score(&s, &ids(&["c", "d", "e", "a"])), Score::default());
        assert_eq!(
            score(&s, &ids(&["a", "f"])),
            Score {
                top1: true,
                top3: true,
                forbidden: true
            }
        );
        assert_eq!(score(&s, &[]), Score::default());
    }

    #[test]
    fn median_and_p95() {
        assert_eq!(median(vec![]), 0);
        assert_eq!(median(vec![5, 1, 3]), 3);
        assert_eq!(median(vec![4, 1, 3, 2]), 2);
        let ms = |v: &[u64]| v.iter().map(|&m| Duration::from_millis(m)).collect();
        assert_eq!(p95(vec![]), Duration::ZERO);
        assert_eq!(p95(ms(&[7])), Duration::from_millis(7));
        assert_eq!(
            p95(ms(&(1..=20).rev().collect::<Vec<_>>())),
            Duration::from_millis(19)
        );
        assert_eq!(
            p95(ms(&(1..=14).collect::<Vec<_>>())),
            Duration::from_millis(14)
        );
    }

    #[test]
    fn gates() {
        let hit = || Score {
            top1: true,
            top3: true,
            forbidden: false,
        };
        let top3_only = || Score {
            top1: false,
            top3: true,
            forbidden: false,
        };
        // 6 of 7 top-1 is 85.7%: passes. 5 of 7 is 71.4%: fails.
        let mut outcomes: Vec<Outcome> = (0..6)
            .map(|i| outcome(hit(), 100 * i, 10 * i as u64))
            .collect();
        outcomes.push(outcome(top3_only(), 900, 1000));
        let sum = Summary::new(&outcomes);
        assert_eq!(
            (sum.top1, sum.top3, sum.median_bytes, sum.p95),
            (6, 7, 300, Duration::from_secs(1))
        );
        assert!(sum.passes());

        outcomes[0].score = top3_only();
        assert!(!Summary::new(&outcomes).passes());

        outcomes[0].score = Score {
            top1: true,
            top3: true,
            forbidden: true,
        };
        assert!(
            !Summary::new(&outcomes).passes(),
            "any forbidden finding fails"
        );

        outcomes[0] = Outcome {
            dir: String::new(),
            score: Score::default(),
            response: Err(anyhow::anyhow!("x")),
        };
        let sum = Summary::new(&outcomes);
        assert!(!sum.passes(), "a failed call misses top-3");
        assert_eq!(
            sum.median_bytes, 350,
            "failed calls are left out of size stats"
        );
        assert!(!Summary::new(&[]).passes());
    }

    #[test]
    fn scenarios_are_valid() {
        let all = load_scenarios(None).unwrap();
        assert!(all.len() >= 12, "v0.1 needs at least 12 scenarios");
        for (dir, s) in &all {
            assert!(
                ["diagnose_pod", "diagnose_workload"].contains(&s.tool.as_str()),
                "{dir}: tool"
            );
            assert!(
                !s.forbidden.contains(&s.expected.primary),
                "{dir}: primary is forbidden"
            );
            assert!(
                scenarios_dir().join(dir).join("manifest.yaml").is_file(),
                "{dir}: manifest"
            );
            assert!(
                scenarios_dir().join(dir).join("README.md").is_file(),
                "{dir}: README"
            );
        }
    }
}
