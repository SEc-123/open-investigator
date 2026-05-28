use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

pub fn now_case_id() -> String {
    let now = Utc::now();
    format!(
        "{}-{:09}",
        now.format("case-%Y%m%d-%H%M%S"),
        now.timestamp_subsec_nanos()
    )
}

pub fn truncate_text(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().take(max_chars) {
        out.push(ch);
    }
    if value.chars().count() > max_chars {
        out.push_str("\n...[truncated]...");
    }
    out
}

pub fn parse_since_to_duration(value: &str) -> Duration {
    let v = value.trim().to_ascii_lowercase();
    let re = Regex::new(r"^(\d+)\s*([mhdw])$").ok();
    if let Some(re) = re {
        if let Some(caps) = re.captures(&v) {
            let amount = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<i64>().ok())
                .unwrap_or(7);
            let unit = caps.get(2).map(|m| m.as_str()).unwrap_or("d");
            return match unit {
                "m" => Duration::minutes(amount),
                "h" => Duration::hours(amount),
                "d" => Duration::days(amount),
                "w" => Duration::weeks(amount),
                _ => Duration::days(7),
            };
        }
    }
    Duration::days(7)
}

pub fn since_cutoff(value: &str) -> DateTime<Utc> {
    Utc::now() - parse_since_to_duration(value)
}

pub fn line_contains_any(line: &str, needles: &[&str]) -> bool {
    let lower = line.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

pub fn is_private_or_loopback_ip(ip: &str) -> bool {
    let parts: Vec<_> = ip.split('.').collect();
    if parts.len() != 4 {
        return ip == "::1"
            || ip.starts_with("fe80:")
            || ip.starts_with("fc")
            || ip.starts_with("fd");
    }
    let octets: Option<Vec<u8>> = parts.iter().map(|p| p.parse::<u8>().ok()).collect();
    let Some(o) = octets else {
        return false;
    };
    matches!(
        (o[0], o[1]),
        (10, _) | (127, _) | (172, 16..=31) | (192, 168)
    )
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))
}

pub fn read_to_string_lossy(path: &Path, max_bytes: usize) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let bytes = if bytes.len() > max_bytes {
        &bytes[..max_bytes]
    } else {
        &bytes[..]
    };
    Ok(String::from_utf8_lossy(bytes).to_string())
}

pub fn collect_files_limited(
    roots: &[PathBuf],
    max_depth: usize,
    max_files: usize,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in roots {
        collect_files_inner(root, 0, max_depth, max_files, &mut out);
        if out.len() >= max_files {
            break;
        }
    }
    out
}

fn collect_files_inner(
    path: &Path,
    depth: usize,
    max_depth: usize,
    max_files: usize,
    out: &mut Vec<PathBuf>,
) {
    if out.len() >= max_files || depth > max_depth {
        return;
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        return;
    }
    if meta.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if !meta.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        collect_files_inner(&entry.path(), depth + 1, max_depth, max_files, out);
        if out.len() >= max_files {
            break;
        }
    }
}

pub fn path_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
}

pub fn file_modified_after(path: &Path, cutoff: DateTime<Utc>) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = meta.modified() else {
        return false;
    };
    let dt: DateTime<Utc> = modified.into();
    dt >= cutoff
}

pub fn command_exists(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return true;
        }
        #[cfg(windows)]
        {
            for suffix in ["exe", "cmd", "bat", "ps1"] {
                if dir.join(format!("{name}.{suffix}")).exists() {
                    return true;
                }
            }
        }
    }
    false
}
