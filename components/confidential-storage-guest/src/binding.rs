// SPDX-License-Identifier: Apache-2.0
//! Lexical constraints only. Authenticated grants select exact destinations;
//! the agent must also reject mount overlap and perform safe mount resolution.
pub fn destination(value: &str) -> bool {
    if value.len() > 256 || !value.starts_with('/') {
        return false;
    }
    let parts: Vec<_> = value[1..].split('/').collect();
    if parts.is_empty() || parts.len() > 8 || !matches!(parts[0], "models" | "data" | "checkpoints")
    {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 63
            && p.as_bytes()[0].is_ascii_alphanumeric()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    })
}

pub fn overlaps(a: &str, b: &str) -> bool {
    a == "/"
        || b == "/"
        || a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_control_paths_traversal_unicode_and_overlapping_targets() {
        for path in ["/models", "/models/qwen", "/data", "/checkpoints/v1"] {
            assert!(destination(path));
        }
        for path in [
            "/",
            "/etc",
            "/proc",
            "/run/coco",
            "/dev",
            "data",
            "/data/..",
            "/data//x",
            "/data/",
            "/data/é",
            "/data/./x",
        ] {
            assert!(!destination(path));
        }
        assert!(overlaps("/models", "/models/qwen"));
        assert!(overlaps("/data/a", "/data"));
        assert!(overlaps("/", "/data"));
        assert!(!overlaps("/data/a", "/data/ab"));
        assert!(!overlaps("/models/qwen", "/models/embedding"));
    }
}
