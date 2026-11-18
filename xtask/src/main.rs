//! Developer tasks: `cargo xtask kind-up | kind-down | eval [--scenario <id>] [--keep] | docs`.
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
        Some("docs") => docs(),
        _ => {
            bail!("usage: cargo xtask kind-up | kind-down | eval [--scenario <id>] [--keep] | docs")
        }
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

/// Where the API server's audit log lands on this machine (`.dev/audit/audit.log`).
fn audit_dir() -> PathBuf {
    root().join(".dev/audit")
}

/// The kind cluster: one node whose API server writes an audit log of the kind admin's writes
/// (`xtask/kind/audit-policy.yaml`) to [`audit_dir`], so tests can check what was sent.
fn kind_config() -> String {
    let policy = root().join("xtask/kind/audit-policy.yaml");
    format!(
        r#"kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - {{hostPath: "{policy}", containerPath: /etc/kubernetes/audit/policy.yaml, readOnly: true}}
      - {{hostPath: "{log}", containerPath: /var/log/kubernetes/audit}}
    kubeadmConfigPatches:
      # kind renders kubeadm v1beta3 (extraArgs a map) for older node images and v1beta4
      # (extraArgs a list) for newer ones; each patch applies to its own version.
      - |
        apiVersion: kubeadm.k8s.io/v1beta3
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            audit-policy-file: /etc/kubernetes/audit/policy.yaml
            audit-log-path: /var/log/kubernetes/audit/audit.log
            audit-log-maxsize: "50"
            audit-log-maxbackup: "1"
{volumes}
      - |
        apiVersion: kubeadm.k8s.io/v1beta4
        kind: ClusterConfiguration
        apiServer:
          extraArgs:
            - {{name: audit-policy-file, value: /etc/kubernetes/audit/policy.yaml}}
            - {{name: audit-log-path, value: /var/log/kubernetes/audit/audit.log}}
            - {{name: audit-log-maxsize, value: "50"}}
            - {{name: audit-log-maxbackup, value: "1"}}
{volumes}
"#,
        policy = policy.display(),
        log = audit_dir().display(),
        volumes = "          extraVolumes:
            - {name: audit-policy, hostPath: /etc/kubernetes/audit, mountPath: /etc/kubernetes/audit, readOnly: true, pathType: DirectoryOrCreate}
            - {name: audit-log, hostPath: /var/log/kubernetes/audit, mountPath: /var/log/kubernetes/audit, pathType: DirectoryOrCreate}",
    )
}

fn kind_up() -> Result<()> {
    std::fs::create_dir_all(audit_dir())?;
    let clusters = output(Command::new("kind").args(["get", "clusters"]))?;
    if clusters.lines().any(|c| c == CLUSTER) {
        println!("reusing kind cluster {CLUSTER}");
        let config = output(Command::new("kind").args(["get", "kubeconfig", "--name", CLUSTER]))?;
        std::fs::write(kubeconfig(), config)?;
        if !audit_dir().join("audit.log").exists() {
            println!(
                "warning: this cluster writes no audit log to {}; the write-safety kind test needs it: `cargo xtask kind-down && cargo xtask kind-up` recreates the cluster",
                audit_dir().display()
            );
        }
    } else {
        let config = root().join(".dev/kind-config.yaml");
        std::fs::write(&config, kind_config())?;
        // CI passes each matrix image; the default is the newest.
        let image = std::env::var("K8S_MCP_KIND_IMAGE").unwrap_or_else(|_| NODE_IMAGE.into());
        run(Command::new("kind")
            .args([
                "create", "cluster", "--name", CLUSTER, "--image", &image, "--config",
            ])
            .arg(&config)
            .arg("--kubeconfig")
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

/// Regenerate `docs/tools.md` and `docs/rules.md` from the tool registry and rule catalogue.
fn docs() -> Result<()> {
    run(Command::new(env!("CARGO"))
        .current_dir(root())
        .args([
            "test",
            "-p",
            "k8s-mcp-server",
            "--bin",
            "k8s-mcp",
            "docs_are_current",
        ])
        .env("K8S_MCP_UPDATE_DOCS", "1"))
}
