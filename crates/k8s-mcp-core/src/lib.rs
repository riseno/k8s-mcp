#![forbid(unsafe_code)]
//! Core building blocks shared by every k8s-mcp crate: findings, the output envelope,
//! policy, redaction, audit and cluster/context management.

pub mod audit;
pub mod cluster;
pub mod envelope;
pub mod error;
pub mod finding;
pub mod policy;
pub mod quantity;
pub mod redact;
pub mod text;

pub use error::{Error, Result};
