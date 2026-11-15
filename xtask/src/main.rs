//! Developer tasks: `cargo xtask kind-up | kind-down | eval [--scenario <id>] [--keep]`.
//!
//! Every cluster command goes through [`kubectl`], which pins the kind-only kubeconfig in
//! `.dev/kubeconfig` and the `kind-k8s-mcp-dev` context, so `~/.kube/config` is never used.

mod eval;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

const CLUSTER: &str = "k8s-mcp-dev";
const CONTEXT: &str = "kind-k8s-mcp-dev";
/// Newest node image published with kind v0.33.0 (digest from its release notes).
const NODE_IMAGE: &str =
    "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5";
const METRICS_SERVER: &str =
    "https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.9.1/components.yaml";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("kind-up") => kind_up(),
        Some("kind-down") => kind_down(),
        Some("eval") => eval::main(&args[1..]),
        _ => bail!("usage: cargo xtask kind-up | kind-down | eval [--scenario <id>] [--keep]"),
    }
}

fn root() -> &'static Path {
    let xtask = Path::new(env!("CARGO_MANIFEST_DIR"));
    xtask.parent().unwrap_or(xtask)
}

fn kubeconfig() -> PathBuf {
    root().join(".dev/kubeconfig")
}

/// `kubectl` pinned to the kind kubeconfig and context.
fn kubectl() -> Command {
    let mut cmd = Command::new("kubectl");
    cmd.arg("--kubeconfig")
        .arg(kubeconfig())
        .args(["--context", CONTEXT]);
    cmd
}

/// Run with inherited stdio; fail on a non-zero exit.
fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().with_context(|| format!("spawn {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} failed: {status}");
    }
    Ok(())
}

/// Run and return stdout; fail with stderr on a non-zero exit.
fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().with_context(|| format!("spawn {cmd:?}"))?;
    if !out.status.success() {
        bail!(
            "{cmd:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Refuse to continue unless the kubeconfig points the kind context at a local API server.
fn verify_context() -> Result<()> {
    let server = output(kubectl().args([
        "config",
        "view",
        "--minify",
        "-o",
        "jsonpath={.clusters[0].cluster.server}",
    ]))?;
    if !server.starts_with("https://127.0.0.1:") {
        bail!(
            "{CONTEXT} in {} points at {server:?}, not a local kind cluster",
            kubeconfig().display()
        );
    }
    Ok(())
}

fn kind_up() -> Result<()> {
    std::fs::create_dir_all(root().join(".dev"))?;
    let clusters = output(Command::new("kind").args(["get", "clusters"]))?;
    if clusters.lines().any(|c| c == CLUSTER) {
        println!("reusing kind cluster {CLUSTER}");
        let config = output(Command::new("kind").args(["get", "kubeconfig", "--name", CLUSTER]))?;
        std::fs::write(kubeconfig(), config)?;
    } else {
        run(Command::new("kind")
            .args([
                "create",
                "cluster",
                "--name",
                CLUSTER,
                "--image",
                NODE_IMAGE,
                "--kubeconfig",
            ])
            .arg(kubeconfig()))?;
    }
    verify_context()?;

    let args = kubectl()
        .args(["get", "deploy", "metrics-server", "-n", "kube-system", "-o"])
        .arg("jsonpath={.spec.template.spec.containers[0].args}")
        .output()?;
    if !String::from_utf8_lossy(&args.stdout).contains("--kubelet-insecure-tls") {
        run(kubectl().args(["apply", "-f", METRICS_SERVER]))?;
        run(kubectl().args([
            "patch",
            "deploy",
            "metrics-server",
            "-n",
            "kube-system",
            "--type=json",
            "-p",
            r#"[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]"#,
        ]))?;
    }
    run(kubectl().args([
        "wait",
        "--for=condition=Ready",
        "nodes",
        "--all",
        "--timeout=180s",
    ]))?;
    run(kubectl().args([
        "rollout",
        "status",
        "deploy/metrics-server",
        "-n",
        "kube-system",
        "--timeout=180s",
    ]))?;
    println!(
        "kind cluster {CLUSTER} ready; kubeconfig {}",
        kubeconfig().display()
    );
    Ok(())
}

fn kind_down() -> Result<()> {
    run(Command::new("kind")
        .args(["delete", "cluster", "--name", CLUSTER, "--kubeconfig"])
        .arg(kubeconfig()))
}
