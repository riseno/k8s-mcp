//! Helm release inspection, opt-in (`--allow-helm-releases`): `helm_releases` and
//! `helm_release`, decoded from Helm 3's release records (Secrets labeled `owner=helm`).
//!
//! Only metadata, status, failure descriptions and notes are deserialised: values, manifests,
//! hooks and chart files are skipped by the deserializer, so no code path can show them.

use std::collections::BTreeMap;
use std::io::Read as _;

use flate2::read::GzDecoder;
use jiff::Timestamp;
use k8s_mcp_core::envelope::Section;
use k8s_mcp_core::text::age;
use k8s_mcp_core::{Error, Result};
use k8s_mcp_diagnose::Unavailable;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams, PartialObjectMeta};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::{Scope, check_name, ensure_namespace, envelope, list_meta_scoped, scope, soft};
use crate::read::add_notes;
use crate::{Ctx, Envelope};

/// Releases `helm_releases` decodes at most; revisions `helm_release` shows at most.
const MAX_RELEASES: usize = 100;
const MAX_REVISIONS: usize = 10;
/// Notes lines shown at most.
const MAX_NOTES: usize = 40;
/// Decompressed size of one release record at most: a gzip bomb stops here.
const MAX_RELEASE_BYTES: u64 = 32 * 1024 * 1024;

/// Inputs for `helm_releases`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HelmReleasesInput {
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// List the releases of every allowed namespace.
    #[serde(default)]
    pub all_namespaces: bool,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// Inputs for `helm_release`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HelmReleaseInput {
    /// Release name.
    pub name: String,
    /// Namespace (default: the context's namespace).
    pub namespace: Option<String>,
    /// Kubeconfig context.
    pub context: Option<String>,
}

/// The fields of a release record that are read.
#[derive(Default, Deserialize)]
struct Release {
    #[serde(default)]
    info: Info,
    #[serde(default)]
    chart: Chart,
}

#[derive(Default, Deserialize)]
struct Info {
    #[serde(default)]
    status: String,
    last_deployed: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    notes: String,
}

#[derive(Default, Deserialize)]
struct Chart {
    #[serde(default)]
    metadata: ChartMeta,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChartMeta {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    app_version: String,
}

/// One revision's record: its Secret's metadata (name, namespace, `name`/`version`/`status`
/// labels).
struct Record {
    secret: String,
    namespace: String,
    release: String,
    revision: u32,
    status: String,
}

fn record(m: &PartialObjectMeta<Secret>) -> Option<Record> {
    let labels = m.metadata.labels.as_ref()?;
    Some(Record {
        secret: m.metadata.name.clone()?,
        namespace: m.metadata.namespace.clone().unwrap_or_default(),
        release: labels.get("name")?.clone(),
        revision: labels.get("version")?.parse().ok()?,
        status: labels.get("status").cloned().unwrap_or_default(),
    })
}

async fn records(ctx: &Ctx, sc: &Scope, selector: &str) -> Result<(Vec<Record>, Vec<Unavailable>)> {
    let mut notes = Vec::new();
    let metas = list_meta_scoped::<Secret>(
        ctx,
        sc,
        &ListParams::default().labels(selector),
        "Helm release records",
        &mut notes,
    )
    .await
    .map_err(|e| {
        if e.is_forbidden() {
            Error::Forbidden(format!(
                "{e}. Listing Helm releases needs `list` on Secrets (Helm stores releases as Secrets); in-cluster, set the chart value helmReleases.enabled=true"
            ))
        } else {
            e
        }
    })?;
    Ok((metas.iter().filter_map(record).collect(), notes))
}

/// Read and decode one revision's record.
async fn read(sc: &Scope, r: &Record) -> Result<Release> {
    let secret = Api::<Secret>::namespaced(sc.target.client.clone(), &r.namespace)
        .get(&r.secret)
        .await
        .map_err(|e| {
            Error::kube(
                format!("get Helm release record {}/{}", r.namespace, r.secret),
                &e,
            )
        })?;
    let raw = secret
        .data
        .as_ref()
        .and_then(|d| d.get("release"))
        .ok_or_else(|| {
            Error::Api(format!(
                "Helm release record {}/{} has no release data",
                r.namespace, r.secret
            ))
        })?;
    decode(&raw.0).ok_or_else(|| {
        Error::Api(format!(
            "Helm release record {}/{} is not a Helm 3 release (base64, gzip, JSON)",
            r.namespace, r.secret
        ))
    })
}

/// Helm 3's encoding: base64 text of (usually gzip-compressed) JSON.
fn decode(data: &[u8]) -> Option<Release> {
    let bytes = base64(data)?;
    let json = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        GzDecoder::new(bytes.as_slice())
            .take(MAX_RELEASE_BYTES)
            .read_to_end(&mut out)
            .ok()?;
        out
    } else {
        bytes
    };
    serde_json::from_slice(&json).ok()
}

/// Standard-alphabet base64, padding and whitespace allowed.
fn base64(text: &[u8]) -> Option<Vec<u8>> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in text.iter().filter(|c| !c.is_ascii_whitespace()) {
        if c == b'=' {
            break;
        }
        acc = (acc << 6) | u32::from(value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn updated(now: Timestamp, info: &Info) -> String {
    info.last_deployed
        .as_deref()
        .and_then(|t| t.parse::<Timestamp>().ok())
        .map_or_else(|| "-".to_owned(), |t| age(now, t))
}

fn chart(meta: &ChartMeta) -> String {
    format!("{}-{}", meta.name, meta.version)
}

/// The Helm releases in a namespace (or every allowed namespace): latest revision, status,
/// chart and app version.
pub async fn helm_releases(ctx: &Ctx, input: HelmReleasesInput) -> Result<Envelope> {
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        input.all_namespaces,
    )
    .await?;
    let (all, mut notes) = records(ctx, &sc, "owner=helm").await?;
    if all.is_empty() {
        ensure_namespace(&sc).await?;
    }
    let mut latest: BTreeMap<(String, String), Record> = BTreeMap::new();
    for r in all {
        let key = (r.namespace.clone(), r.release.clone());
        if latest.get(&key).is_none_or(|l| r.revision > l.revision) {
            latest.insert(key, r);
        }
    }
    let total = latest.len();
    let now = ctx.now();
    let mut items = Vec::new();
    for r in latest.into_values().take(MAX_RELEASES) {
        let release = soft(
            read(&sc, &r).await,
            &format!("Helm release {}/{}", r.namespace, r.release),
            &mut notes,
        )?;
        let release = release.unwrap_or_default();
        items.push(json!({
            "name": r.release,
            "ns": r.namespace,
            "revision": r.revision,
            "status": if release.info.status.is_empty() { r.status } else { release.info.status.clone() },
            "chart": chart(&release.chart.metadata),
            "app_version": release.chart.metadata.app_version,
            "updated": updated(now, &release.info),
        }));
    }
    let failing = items
        .iter()
        .filter(|i| {
            !matches!(
                i["status"].as_str(),
                Some("deployed" | "superseded" | "uninstalled")
            )
        })
        .count();
    let mut e = envelope(
        &sc,
        format!(
            "{total} Helm release(s){}{}.",
            if failing > 0 {
                format!(", {failing} not deployed")
            } else {
                String::new()
            },
            if total > MAX_RELEASES {
                format!(" (first {MAX_RELEASES} shown)")
            } else {
                String::new()
            }
        ),
    );
    e.columns = vec![
        "name",
        "ns",
        "revision",
        "status",
        "chart",
        "app_version",
        "updated",
    ];
    e.items = items;
    e.items_untrusted = Some("helm");
    if total > MAX_RELEASES {
        e.truncated = true;
        e.omitted.items = total - MAX_RELEASES;
    }
    add_notes(&mut e, &notes);
    Ok(e)
}

/// One Helm release: its revisions (status, chart, app version, failure description) and
/// the latest revision's notes.
pub async fn helm_release(ctx: &Ctx, input: HelmReleaseInput) -> Result<Envelope> {
    check_name("release", &input.name)?;
    let sc = scope(
        ctx,
        input.context.as_deref(),
        input.namespace.as_deref(),
        false,
    )
    .await?;
    let ns = sc.namespace.clone().unwrap_or_default();
    let (mut revs, mut notes) =
        records(ctx, &sc, &format!("owner=helm,name={}", input.name)).await?;
    revs.retain(|r| r.release == input.name);
    if revs.is_empty() {
        ensure_namespace(&sc).await?;
        return Err(Error::NotFound(format!(
            "no Helm release {:?} in namespace {ns}: helm_releases lists the releases",
            input.name
        )));
    }
    revs.sort_by_key(|r| std::cmp::Reverse(r.revision));
    let total = revs.len();
    let now = ctx.now();
    let mut items: Vec<Value> = Vec::new();
    let mut latest: Option<Release> = None;
    for r in revs.iter().take(MAX_REVISIONS) {
        let release = soft(
            read(&sc, r).await,
            &format!("Helm release revision {}", r.revision),
            &mut notes,
        )?
        .unwrap_or_default();
        items.push(json!({
            "revision": r.revision,
            "status": if release.info.status.is_empty() { r.status.clone() } else { release.info.status.clone() },
            "chart": chart(&release.chart.metadata),
            "app_version": release.chart.metadata.app_version,
            "updated": updated(now, &release.info),
            "description": ctx.redactor.text(&release.info.description),
        }));
        latest.get_or_insert(release);
    }
    let head = &items[0];
    let mut e = envelope(
        &sc,
        format!(
            "Helm release {} ({ns}): revision {}, {}, chart {}, app {}; {total} revision(s).",
            input.name,
            head["revision"],
            head["status"].as_str().unwrap_or("-"),
            head["chart"].as_str().unwrap_or("-"),
            head["app_version"].as_str().unwrap_or("-"),
        ),
    );
    e.columns = vec![
        "revision",
        "status",
        "chart",
        "app_version",
        "updated",
        "description",
    ];
    e.items = items;
    e.items_untrusted = Some("helm");
    if total > MAX_REVISIONS {
        e.truncated = true;
        e.omitted.items = total - MAX_REVISIONS;
    }
    let notes_text = latest.map(|r| r.info.notes).unwrap_or_default();
    if !notes_text.trim().is_empty() {
        let lines = ctx.redactor.lines(notes_text.lines().take(MAX_NOTES));
        e.sections.push(Section {
            title: "NOTES (latest revision, redacted)".into(),
            lines,
            untrusted: Some(vec![("source".into(), "helm-notes".into())]),
        });
    }
    add_notes(&mut e, &notes);
    Ok(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_the_standard_alphabet() {
        assert_eq!(base64(b"aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert_eq!(base64(b"aGVsbG8\ngd29y bGQ").unwrap(), b"hello world");
        assert_eq!(base64(b"+/+/").unwrap(), [0xfb, 0xff, 0xbf]);
        assert!(base64(b"not base64!").is_none());
    }

    /// Values are never deserialised: only the metadata fields survive decoding.
    #[test]
    fn decodes_gzip_and_plain_records() {
        let json = br#"{"name":"web","config":{"password":"hunter2"},"manifest":"kind: Secret","info":{"status":"failed","description":"Upgrade failed: timed out","notes":"Visit http://web"},"chart":{"metadata":{"name":"nginx","version":"1.2.3","appVersion":"1.27"}}}"#;
        let mut gz = Vec::new();
        {
            use std::io::Write as _;
            let mut w = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            w.write_all(json).unwrap();
            w.finish().unwrap();
        }
        for raw in [gz.as_slice(), json.as_slice()] {
            let r = decode(encode(raw).as_bytes()).unwrap();
            assert_eq!(
                (r.info.status.as_str(), r.info.description.as_str()),
                ("failed", "Upgrade failed: timed out")
            );
            assert_eq!(chart(&r.chart.metadata), "nginx-1.2.3");
            assert_eq!(r.chart.metadata.app_version, "1.27");
        }
        assert!(decode(b"!!").is_none());
    }

    /// Test helper: standard base64.
    pub(crate) fn encode(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
