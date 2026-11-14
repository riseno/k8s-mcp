//! Kubernetes resource quantity parsing (`250m`, `1.5`, `128Mi`, `1G`, `2e3`).

/// Parse a CPU quantity into millicores. Returns `None` for malformed input.
pub fn cpu_millis(q: &str) -> Option<i64> {
    let q = q.trim();
    let (num, mult) = if let Some(n) = q.strip_suffix('n') {
        (n, 1e-6)
    } else if let Some(n) = q.strip_suffix('u') {
        (n, 1e-3)
    } else if let Some(n) = q.strip_suffix('m') {
        (n, 1.0)
    } else {
        (q, 1000.0)
    };
    let v: f64 = num.parse().ok()?;
    #[allow(clippy::cast_possible_truncation)]
    Some((v * mult).round() as i64)
}

/// Parse a memory (or any byte) quantity into bytes. Returns `None` for malformed input.
pub fn bytes(q: &str) -> Option<i64> {
    const SUFFIXES: &[(&str, f64)] = &[
        ("Ki", 1024.0),
        ("Mi", 1_048_576.0),
        ("Gi", 1_073_741_824.0),
        ("Ti", 1_099_511_627_776.0),
        ("Pi", 1_125_899_906_842_624.0),
        ("Ei", 1_152_921_504_606_846_976.0),
        ("k", 1e3),
        ("M", 1e6),
        ("G", 1e9),
        ("T", 1e12),
        ("P", 1e15),
        ("E", 1e18),
        ("m", 1e-3),
    ];
    let q = q.trim();
    let (num, mult) = SUFFIXES
        .iter()
        .find_map(|(s, m)| q.strip_suffix(s).map(|n| (n, *m)))
        .unwrap_or((q, 1.0));
    let v: f64 = num.parse().ok()?;
    #[allow(clippy::cast_possible_truncation)]
    Some((v * mult).round() as i64)
}

/// Human-readable bytes using binary units, e.g. `128Mi`.
pub fn fmt_bytes(b: i64) -> String {
    const UNITS: &[(&str, i64)] = &[("Gi", 1 << 30), ("Mi", 1 << 20), ("Ki", 1 << 10)];
    for (u, size) in UNITS {
        if b.abs() >= *size {
            #[allow(clippy::cast_precision_loss)]
            let v = b as f64 / *size as f64;
            return if (v - v.round()).abs() < 0.05 {
                format!("{v:.0}{u}")
            } else {
                format!("{v:.1}{u}")
            };
        }
    }
    format!("{b}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu() {
        assert_eq!(cpu_millis("250m"), Some(250));
        assert_eq!(cpu_millis("2"), Some(2000));
        assert_eq!(cpu_millis("0.5"), Some(500));
        assert_eq!(cpu_millis("1500000n"), Some(2));
        assert_eq!(cpu_millis("64"), Some(64_000));
        assert_eq!(cpu_millis("abc"), None);
    }

    #[test]
    fn memory() {
        assert_eq!(bytes("128Mi"), Some(134_217_728));
        assert_eq!(bytes("1G"), Some(1_000_000_000));
        assert_eq!(bytes("512Ki"), Some(524_288));
        assert_eq!(bytes("1024"), Some(1024));
        assert_eq!(bytes("2e3"), Some(2000));
        assert_eq!(bytes("x"), None);
        assert_eq!(fmt_bytes(134_217_728), "128Mi");
        assert_eq!(fmt_bytes(1_610_612_736), "1.5Gi");
    }
}
