#![forbid(unsafe_code)]
// Test-only crate: panicking on bad fixtures is the right behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::missing_panics_doc)]
//! Fixtures for k8s-mcp tests: multi-document YAML files under `fixtures/` loaded into
//! k8s-openapi types, and a fixed clock.

use std::path::PathBuf;

use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// The fixed "now" every fixture is written against: `2026-11-14T12:00:00Z`.
pub fn now() -> Timestamp {
    "2026-11-14T12:00:00Z".parse().unwrap()
}

/// Path of a file under `fixtures/`.
pub fn path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

/// A multi-document YAML fixture.
#[derive(Debug, Clone, Default)]
pub struct Fixture {
    /// Every document, as JSON.
    pub objects: Vec<Value>,
}

/// Load `fixtures/<name>` (for example `pods/crashloop-oom.yaml`).
pub fn load(name: &str) -> Fixture {
    let p = path(name);
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    let objects: Vec<Value> =
        serde_saphyr::from_multiple(&text).unwrap_or_else(|e| panic!("parse {}: {e}", p.display()));
    Fixture {
        objects: objects.into_iter().filter(|v| !v.is_null()).collect(),
    }
}

impl Fixture {
    /// All documents of `kind`.
    pub fn all<T: DeserializeOwned>(&self, kind: &str) -> Vec<T> {
        self.objects
            .iter()
            .filter(|o| o["kind"] == kind)
            .map(|o| serde_json::from_value(o.clone()).unwrap_or_else(|e| panic!("{kind}: {e}")))
            .collect()
    }

    /// The single document of `kind`; panics if there is not exactly one.
    pub fn one<T: DeserializeOwned>(&self, kind: &str) -> T {
        let mut all = self.all::<T>(kind);
        assert_eq!(all.len(), 1, "expected exactly one {kind}");
        all.remove(0)
    }

    /// The first document of `kind`, if any.
    pub fn first<T: DeserializeOwned>(&self, kind: &str) -> Option<T> {
        self.all::<T>(kind).into_iter().next()
    }
}
