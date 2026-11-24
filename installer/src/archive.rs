//! Hardened release manifest parsing, SHA-256 verification, zip/tar.gz extraction,
//! binary header inspection, and atomic install receipts.

use crate::validation::{
    constant_time_hex_eq, validate_https_url, validate_relative_archive_path, validate_sha256_hex,
};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::{Archive as TarArchive, EntryType};
use thiserror::Error;
use zip::ZipArchive;

pub const MAX_MANIFEST_BYTES: usize = 65_536;
pub const MAX_LINUX_TEXT_MANIFEST_BYTES: usize = 1024;
pub const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("invalid URL or checksum parameter: {0}")]
    Validation(#[from] crate::validation::ValidationError),
    #[error("refusing symlink at path: {0}")]
    SymlinkForbidden(String),
    #[error("archive size {actual} exceeds maximum allowed {max} bytes")]
    SizeLimitExceeded { actual: u64, max: u64 },
    #[error("archive entry count {actual} exceeds maximum allowed {max}")]
    EntryLimitExceeded { actual: usize, max: usize },
    #[error("duplicate or case-colliding archive path: {0}")]
    DuplicateMember(String),
    #[error("forbidden archive member type (link/device/fifo) at: {0}")]
    ForbiddenMemberType(String),
    #[error("archive symlink target escapes extraction root: {0}")]
    SymlinkEscape(String),
    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("unrecognized or unsupported binary format: {0}")]
    InvalidBinary(String),
    #[error("HTTPS download failed: {0}")]
    DownloadFailed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseBuildEntry {
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub format: Option<u32>,
    pub version: String,
    pub revision: String,
    pub builds: BTreeMap<String, ReleaseBuildEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinuxTextManifest {
    pub format: u32,
    pub version: String,
    pub revision: String,
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractionLimits {
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_single_file_bytes: u64,
    pub allow_bundle_internal_symlinks: bool,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            max_total_bytes: MAX_ARCHIVE_BYTES,
            max_single_file_bytes: MAX_ARCHIVE_BYTES,
            allow_bundle_internal_symlinks: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    Zip,
    TarGz,
}

/// Detects whether an archive file is a ZIP or gzip-compressed tar archive by magic bytes (with extension fallback).
pub fn detect_archive_kind(path: &Path) -> Result<ArchiveKind, ArchiveError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(ArchiveError::SymlinkForbidden(path.display().to_string()));
    }
    if !meta.is_file() {
        return Err(ArchiveError::InvalidManifest(format!(
            "not a regular file: {}",
            path.display()
        )));
    }
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    if n >= 4
        && (magic == [0x50, 0x4b, 0x03, 0x04]
            || magic == [0x50, 0x4b, 0x05, 0x06]
            || magic == [0x50, 0x4b, 0x07, 0x08])
    {
        return Ok(ArchiveKind::Zip);
    }
    if n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return Ok(ArchiveKind::TarGz);
    }
    let lower = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if lower.ends_with(".zip") {
        return Ok(ArchiveKind::Zip);
    }
    if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        return Ok(ArchiveKind::TarGz);
    }
    Err(ArchiveError::InvalidManifest(format!(
        "unrecognized archive format (expected ZIP or .tar.gz): {}",
        path.display()
    )))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Elf,
    MachO,
    Pe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub arch: String,
    pub universal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallReceipt {
    pub version: u32,
    pub component: String,
    pub revision: String,
    pub platform: String,
    pub arch: String,
    pub installed_at_unix: u64,
    pub archive_sha256: String,
    pub files: BTreeMap<String, String>,
}

/// Validates a safe single-segment release archive filename.
pub fn validate_release_filename(name: &str) -> Result<(), ArchiveError> {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('.')
        || name.starts_with('-')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        || name.contains("..")
    {
        return Err(ArchiveError::InvalidManifest(format!(
            "unsafe release filename: {name}"
        )));
    }
    if !(name.ends_with(".zip") || name.ends_with(".tar.gz") || name.ends_with(".tgz")) {
        return Err(ArchiveError::InvalidManifest(format!(
            "unsupported release extension: {name}"
        )));
    }
    Ok(())
}

fn is_valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.chars().next().is_some_and(|c| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

fn is_valid_revision(r: &str) -> bool {
    r.len() == 40 && r.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// Parses and strictly validates a JSON release manifest (`latest.json` / `windows-latest.json`).
pub fn parse_release_manifest_json(raw: &[u8]) -> Result<ReleaseManifest, ArchiveError> {
    if raw.len() > MAX_MANIFEST_BYTES {
        return Err(ArchiveError::InvalidManifest(
            "manifest exceeds 64 KiB limit".into(),
        ));
    }
    let manifest: ReleaseManifest = serde_json::from_slice(raw)?;
    if let Some(fmt) = manifest.format {
        if fmt != 1 {
            return Err(ArchiveError::InvalidManifest(format!(
                "unsupported manifest format {fmt}"
            )));
        }
    }
    if !is_valid_version(&manifest.version) {
        return Err(ArchiveError::InvalidManifest("invalid version".into()));
    }
    if !is_valid_revision(&manifest.revision) {
        return Err(ArchiveError::InvalidManifest(
            "invalid 40-hex revision".into(),
        ));
    }
    if manifest.builds.is_empty() {
        return Err(ArchiveError::InvalidManifest(
            "builds map must not be empty".into(),
        ));
    }
    for (target, entry) in &manifest.builds {
        if target.is_empty()
            || target.len() > 32
            || !target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            return Err(ArchiveError::InvalidManifest(format!(
                "invalid target key: {target}"
            )));
        }
        validate_release_filename(&entry.file)?;
        validate_sha256_hex(&entry.sha256)?;
        if entry.bytes == 0 || entry.bytes > MAX_ARCHIVE_BYTES {
            return Err(ArchiveError::InvalidManifest(format!(
                "invalid archive byte count for {target}"
            )));
        }
    }
    Ok(manifest)
}

/// Parses and validates a 6-line `linux-latest.txt` key=value manifest without executing anything.
pub fn parse_linux_text_manifest(raw: &[u8]) -> Result<LinuxTextManifest, ArchiveError> {
    if raw.len() > MAX_LINUX_TEXT_MANIFEST_BYTES {
        return Err(ArchiveError::InvalidManifest(
            "linux-latest.txt exceeds 1024 bytes".into(),
        ));
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| ArchiveError::InvalidManifest("non-UTF8 manifest".into()))?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() != 6 {
        return Err(ArchiveError::InvalidManifest(format!(
            "expected exactly 6 lines, got {}",
            lines.len()
        )));
    }
    let mut map = BTreeMap::new();
    for line in lines {
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| ArchiveError::InvalidManifest("missing '=' in manifest line".into()))?;
        if map.insert(k.to_string(), v.to_string()).is_some() {
            return Err(ArchiveError::InvalidManifest(format!(
                "duplicate key {k} in manifest"
            )));
        }
    }
    let get = |key: &str| -> Result<&str, ArchiveError> {
        map.get(key)
            .map(String::as_str)
            .ok_or_else(|| ArchiveError::InvalidManifest(format!("missing key {key}")))
    };
    let format: u32 = get("format")?
        .parse()
        .map_err(|_| ArchiveError::InvalidManifest("invalid format".into()))?;
    if format != 1 {
        return Err(ArchiveError::InvalidManifest("format must be 1".into()));
    }
    let version = get("version")?.to_string();
    if !is_valid_version(&version) {
        return Err(ArchiveError::InvalidManifest("invalid version".into()));
    }
    let revision = get("revision")?.to_string();
    if !is_valid_revision(&revision) {
        return Err(ArchiveError::InvalidManifest("invalid revision".into()));
    }
    let file = get("file")?.to_string();
    validate_release_filename(&file)?;
    let sha256 = validate_sha256_hex(get("sha256")?)?;
    let bytes: u64 = get("bytes")?
        .parse()
        .map_err(|_| ArchiveError::InvalidManifest("invalid bytes".into()))?;
    if bytes == 0 || bytes > MAX_ARCHIVE_BYTES {
        return Err(ArchiveError::InvalidManifest("invalid archive size".into()));
    }
    Ok(LinuxTextManifest {
        format,
        version,
        revision,
        file,
        sha256,
        bytes,
    })
}

/// Computes lowercase SHA-256 hex digest of a regular file (refusing symlinks).
pub fn compute_file_sha256(path: &Path) -> Result<String, ArchiveError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(ArchiveError::SymlinkForbidden(path.display().to_string()));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verifies an archive file exists as a regular file (no symlink), fits `max_bytes`, and matches SHA-256.
pub fn verify_archive_file(
    path: &Path,
    expected_sha256: &str,
    max_bytes: u64,
) -> Result<u64, ArchiveError> {
    let expected = validate_sha256_hex(expected_sha256)?;
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(ArchiveError::SymlinkForbidden(path.display().to_string()));
    }
    if !meta.is_file() {
        return Err(ArchiveError::InvalidManifest(format!(
            "not a regular file: {}",
            path.display()
        )));
    }
    let size = meta.len();
    if size == 0 {
        return Err(ArchiveError::InvalidManifest(
            "archive file is empty".into(),
        ));
    }
    if size > max_bytes {
        return Err(ArchiveError::SizeLimitExceeded {
            actual: size,
            max: max_bytes,
        });
    }
    let actual = compute_file_sha256(path)?;
    if !constant_time_hex_eq(&actual, &expected) {
        return Err(ArchiveError::ChecksumMismatch { expected, actual });
    }
    Ok(size)
}

fn ensure_no_symlink_components(root: &Path, rel: &Path) -> Result<(), ArchiveError> {
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        if let Component::Normal(seg) = comp {
            cur.push(seg);
            if let Ok(meta) = fs::symlink_metadata(&cur) {
                if meta.file_type().is_symlink() {
                    return Err(ArchiveError::SymlinkForbidden(cur.display().to_string()));
                }
            }
        }
    }
    Ok(())
}

fn resolve_lexical_inside(root: &Path, candidate_rel: &Path) -> Result<PathBuf, ArchiveError> {
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    for comp in candidate_rel.components() {
        match comp {
            Component::Normal(s) => stack.push(s.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                if stack.pop().is_none() {
                    return Err(ArchiveError::SymlinkEscape(
                        candidate_rel.display().to_string(),
                    ));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ArchiveError::SymlinkEscape(
                    candidate_rel.display().to_string(),
                ));
            }
        }
    }
    let mut out = root.to_path_buf();
    for seg in stack {
        out.push(seg);
    }
    Ok(out)
}

fn create_safe_regular_file(path: &Path, executable: bool) -> Result<File, ArchiveError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if executable { 0o755 } else { 0o644 });
    }
    let file = opts.open(path)?;
    Ok(file)
}

#[cfg(unix)]
fn create_safe_symlink(link_path: &Path, target: &str) -> Result<(), ArchiveError> {
    std::os::unix::fs::symlink(target, link_path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_safe_symlink(link_path: &Path, _target: &str) -> Result<(), ArchiveError> {
    Err(ArchiveError::ForbiddenMemberType(
        link_path.display().to_string(),
    ))
}

fn record_member_unique(
    seen_exact: &mut HashSet<String>,
    seen_folded: &mut HashSet<String>,
    rel_key: &str,
) -> Result<(), ArchiveError> {
    if !seen_exact.insert(rel_key.to_string()) {
        return Err(ArchiveError::DuplicateMember(rel_key.to_string()));
    }
    // Enforce case-uniqueness so macOS/Windows extraction cannot silently clobber files.
    let folded = rel_key.to_ascii_lowercase();
    if !seen_folded.insert(folded) {
        return Err(ArchiveError::DuplicateMember(rel_key.to_string()));
    }
    Ok(())
}

fn cleanup_partial_extraction(extracted: &[PathBuf], created_root: Option<&Path>) {
    for p in extracted.iter().rev() {
        let _ = fs::remove_file(p);
    }
    if let Some(root) = created_root {
        let _ = fs::remove_dir_all(root);
    }
}

/// Safely extracts a ZIP archive with strict path, symlink, case-collision, and zip-bomb bounds.
pub fn extract_zip_safe(
    archive_path: &Path,
    dest_dir: &Path,
    limits: ExtractionLimits,
) -> Result<Vec<PathBuf>, ArchiveError> {
    let meta = fs::symlink_metadata(archive_path)?;
    if meta.file_type().is_symlink() {
        return Err(ArchiveError::SymlinkForbidden(
            archive_path.display().to_string(),
        ));
    }
    let created_dest = fs::symlink_metadata(dest_dir).is_err();
    fs::create_dir_all(dest_dir)?;
    let dest_canon = fs::canonicalize(dest_dir)?;
    let mut extracted = Vec::new();
    match extract_zip_inner(archive_path, &dest_canon, limits, &mut extracted) {
        Ok(()) => Ok(extracted),
        Err(e) => {
            cleanup_partial_extraction(&extracted, created_dest.then_some(dest_canon.as_path()));
            Err(e)
        }
    }
}

fn extract_zip_inner(
    archive_path: &Path,
    dest_dir_canon: &Path,
    limits: ExtractionLimits,
    extracted: &mut Vec<PathBuf>,
) -> Result<(), ArchiveError> {
    let dest_canon = dest_dir_canon.to_path_buf();
    let file = File::open(archive_path)?;
    let mut zip = ZipArchive::new(BufReader::new(file))?;
    if zip.len() > limits.max_entries {
        return Err(ArchiveError::EntryLimitExceeded {
            actual: zip.len(),
            max: limits.max_entries,
        });
    }

    let mut seen_exact = HashSet::new();
    let mut seen_folded = HashSet::new();
    let mut total_bytes: u64 = 0;
    let mut deferred_symlinks: Vec<(PathBuf, PathBuf, String)> = Vec::new();

    for idx in 0..zip.len() {
        let mut entry = zip.by_index(idx)?;
        let raw_name = entry.name().to_string();
        let is_dir = raw_name.ends_with('/') || entry.is_dir();
        let mut clean_raw = raw_name.as_str();
        while let Some(stripped) = clean_raw.strip_prefix("./") {
            clean_raw = stripped;
        }
        let clean_raw = if is_dir {
            clean_raw.trim_end_matches('/')
        } else {
            clean_raw
        };
        if clean_raw.is_empty() || clean_raw == "." {
            continue;
        }

        let rel_path = validate_relative_archive_path(clean_raw)?;
        record_member_unique(&mut seen_exact, &mut seen_folded, clean_raw)?;
        ensure_no_symlink_components(&dest_canon, &rel_path)?;

        let unix_mode = entry.unix_mode();
        let file_type = unix_mode.map_or(0, |m| m & 0o170000);
        // Reject block/char/fifo/socket modes unconditionally.
        if matches!(file_type, 0o060000 | 0o020000 | 0o010000 | 0o140000) {
            return Err(ArchiveError::ForbiddenMemberType(raw_name));
        }
        if entry.is_symlink() || file_type == 0o120000 {
            if !limits.allow_bundle_internal_symlinks {
                return Err(ArchiveError::SymlinkForbidden(raw_name));
            }
            let mut target_bytes = Vec::new();
            entry.by_ref().take(4097).read_to_end(&mut target_bytes)?;
            if target_bytes.len() > 4096 {
                return Err(ArchiveError::SymlinkEscape(raw_name));
            }
            let target_str = String::from_utf8(target_bytes)
                .map_err(|_| ArchiveError::SymlinkEscape(raw_name.clone()))?;
            if target_str.is_empty()
                || target_str.starts_with('/')
                || target_str.contains('\\')
                || target_str.contains('\0')
            {
                return Err(ArchiveError::SymlinkEscape(raw_name));
            }
            let parent_rel = rel_path.parent().unwrap_or_else(|| Path::new(""));
            let combined_rel = parent_rel.join(&target_str);
            let _ = resolve_lexical_inside(&dest_canon, &combined_rel)?;
            if let Some(parent) = dest_canon.join(&rel_path).parent() {
                fs::create_dir_all(parent)?;
            }
            deferred_symlinks.push((rel_path.clone(), dest_canon.join(&rel_path), target_str));
            continue;
        }

        let target_path = dest_canon.join(&rel_path);
        if is_dir {
            fs::create_dir_all(&target_path)?;
            continue;
        }
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let executable = unix_mode.is_some_and(|m| (m & 0o111) != 0);
        let mut out_file = create_safe_regular_file(&target_path, executable)?;
        let mut buf = [0u8; 64 * 1024];
        let mut file_bytes: u64 = 0;
        let mut limited = (&mut entry).take(limits.max_single_file_bytes + 1);
        loop {
            let n = limited.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file_bytes += n as u64;
            if file_bytes > limits.max_single_file_bytes {
                let _ = fs::remove_file(&target_path);
                return Err(ArchiveError::SizeLimitExceeded {
                    actual: file_bytes,
                    max: limits.max_single_file_bytes,
                });
            }
            total_bytes += n as u64;
            if total_bytes > limits.max_total_bytes {
                let _ = fs::remove_file(&target_path);
                return Err(ArchiveError::SizeLimitExceeded {
                    actual: total_bytes,
                    max: limits.max_total_bytes,
                });
            }
            out_file.write_all(&buf[..n])?;
        }
        out_file.flush()?;
        extracted.push(target_path);
    }

    for (rel_path, link_abs, target_str) in deferred_symlinks {
        ensure_no_symlink_components(&dest_canon, &rel_path)?;
        create_safe_symlink(&link_abs, &target_str)?;
        extracted.push(link_abs);
    }

    Ok(())
}

/// Safely extracts a `.tar.gz` archive with strict path, symlink, hardlink, and size bounds.
pub fn extract_tar_gz_safe(
    archive_path: &Path,
    dest_dir: &Path,
    limits: ExtractionLimits,
) -> Result<Vec<PathBuf>, ArchiveError> {
    let meta = fs::symlink_metadata(archive_path)?;
    if meta.file_type().is_symlink() {
        return Err(ArchiveError::SymlinkForbidden(
            archive_path.display().to_string(),
        ));
    }
    let created_dest = fs::symlink_metadata(dest_dir).is_err();
    fs::create_dir_all(dest_dir)?;
    let dest_canon = fs::canonicalize(dest_dir)?;
    let mut extracted = Vec::new();
    match extract_tar_gz_inner(archive_path, &dest_canon, limits, &mut extracted) {
        Ok(()) => Ok(extracted),
        Err(e) => {
            cleanup_partial_extraction(&extracted, created_dest.then_some(dest_canon.as_path()));
            Err(e)
        }
    }
}

fn extract_tar_gz_inner(
    archive_path: &Path,
    dest_dir_canon: &Path,
    limits: ExtractionLimits,
    extracted: &mut Vec<PathBuf>,
) -> Result<(), ArchiveError> {
    let dest_canon = dest_dir_canon.to_path_buf();
    let file = File::open(archive_path)?;
    let gz = GzDecoder::new(BufReader::new(file));
    let mut tar = TarArchive::new(gz);

    let mut seen_exact = HashSet::new();
    let mut seen_folded = HashSet::new();
    let mut entry_count: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut deferred_symlinks: Vec<(PathBuf, PathBuf, String)> = Vec::new();

    for item in tar.entries()? {
        entry_count += 1;
        if entry_count > limits.max_entries {
            return Err(ArchiveError::EntryLimitExceeded {
                actual: entry_count,
                max: limits.max_entries,
            });
        }
        let mut entry = item?;
        let etype = entry.header().entry_type();
        let raw_path = entry.path()?.to_string_lossy().replace('\\', "/");
        let is_dir = etype == EntryType::Directory || raw_path.ends_with('/');
        let mut clean_raw = raw_path.as_str();
        while let Some(stripped) = clean_raw.strip_prefix("./") {
            clean_raw = stripped;
        }
        let clean_raw = clean_raw.trim_end_matches('/');
        if clean_raw.is_empty() || clean_raw == "." {
            continue;
        }
        let rel_path = validate_relative_archive_path(clean_raw)?;
        record_member_unique(&mut seen_exact, &mut seen_folded, clean_raw)?;
        ensure_no_symlink_components(&dest_canon, &rel_path)?;

        match etype {
            EntryType::Directory => {
                fs::create_dir_all(dest_canon.join(&rel_path))?;
            }
            EntryType::Regular | EntryType::Continuous => {
                let target_path = dest_canon.join(&rel_path);
                if let Some(parent) = target_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let executable = entry
                    .header()
                    .mode()
                    .map(|m| (m & 0o111) != 0)
                    .unwrap_or(false);
                let mut out_file = create_safe_regular_file(&target_path, executable)?;
                let mut buf = [0u8; 64 * 1024];
                let mut file_bytes: u64 = 0;
                let mut limited = (&mut entry).take(limits.max_single_file_bytes + 1);
                loop {
                    let n = limited.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    file_bytes += n as u64;
                    if file_bytes > limits.max_single_file_bytes {
                        let _ = fs::remove_file(&target_path);
                        return Err(ArchiveError::SizeLimitExceeded {
                            actual: file_bytes,
                            max: limits.max_single_file_bytes,
                        });
                    }
                    total_bytes += n as u64;
                    if total_bytes > limits.max_total_bytes {
                        let _ = fs::remove_file(&target_path);
                        return Err(ArchiveError::SizeLimitExceeded {
                            actual: total_bytes,
                            max: limits.max_total_bytes,
                        });
                    }
                    out_file.write_all(&buf[..n])?;
                }
                out_file.flush()?;
                extracted.push(target_path);
            }
            EntryType::Symlink => {
                if !limits.allow_bundle_internal_symlinks {
                    return Err(ArchiveError::SymlinkForbidden(clean_raw.to_string()));
                }
                let link_target = entry
                    .link_name()?
                    .ok_or_else(|| ArchiveError::SymlinkEscape(clean_raw.to_string()))?;
                let target_str = link_target.to_string_lossy().to_string();
                if target_str.is_empty()
                    || target_str.starts_with('/')
                    || target_str.contains('\\')
                    || target_str.contains('\0')
                {
                    return Err(ArchiveError::SymlinkEscape(clean_raw.to_string()));
                }
                let parent_rel = rel_path.parent().unwrap_or_else(|| Path::new(""));
                let _ = resolve_lexical_inside(&dest_canon, &parent_rel.join(&target_str))?;
                if let Some(parent) = dest_canon.join(&rel_path).parent() {
                    fs::create_dir_all(parent)?;
                }
                deferred_symlinks.push((rel_path.clone(), dest_canon.join(&rel_path), target_str));
            }
            _ => {
                return Err(ArchiveError::ForbiddenMemberType(clean_raw.to_string()));
            }
        }
        let _ = is_dir;
    }

    for (rel_path, link_abs, target_str) in deferred_symlinks {
        ensure_no_symlink_components(&dest_canon, &rel_path)?;
        create_safe_symlink(&link_abs, &target_str)?;
        extracted.push(link_abs);
    }

    Ok(())
}

/// Inspects an executable's binary header bytes without executing it.
pub fn inspect_binary_header(path: &Path) -> Result<BinaryInfo, ArchiveError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(ArchiveError::SymlinkForbidden(path.display().to_string()));
    }
    if !meta.is_file() {
        return Err(ArchiveError::InvalidBinary("not a regular file".into()));
    }
    let mut file = File::open(path)?;
    let mut buf = vec![0u8; 4096];
    let n = file.read(&mut buf)?;
    buf.truncate(n);
    parse_binary_header_bytes(&buf)
}

/// Parses ELF, Mach-O, or PE executable headers directly from header bytes.
pub fn parse_binary_header_bytes(bytes: &[u8]) -> Result<BinaryInfo, ArchiveError> {
    if bytes.len() < 4 {
        return Err(ArchiveError::InvalidBinary("file too short".into()));
    }
    // 1. ELF 64-bit little-endian
    if bytes.len() >= 20 && &bytes[0..4] == b"\x7fELF" {
        if bytes[4] != 2 || bytes[5] != 1 {
            return Err(ArchiveError::InvalidBinary(
                "expected 64-bit little-endian ELF".into(),
            ));
        }
        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        let arch = match machine {
            0x003e => "x86_64",
            0x00b7 => "arm64",
            other => {
                return Err(ArchiveError::InvalidBinary(format!(
                    "unsupported ELF machine 0x{other:04x}"
                )));
            }
        };
        return Ok(BinaryInfo {
            format: BinaryFormat::Elf,
            arch: arch.to_string(),
            universal: false,
        });
    }

    // 2. Mach-O thin 64-bit LE (`cffaedfe`) or universal fat (`cafebabe`)
    let magic = &bytes[0..4];
    if magic == [0xcf, 0xfa, 0xed, 0xfe] && bytes.len() >= 8 {
        let cputype = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let arch = match cputype {
            0x0100_000c => "arm64",
            0x0100_0007 => "x86_64",
            other => {
                return Err(ArchiveError::InvalidBinary(format!(
                    "unsupported Mach-O cputype 0x{other:08x}"
                )));
            }
        };
        return Ok(BinaryInfo {
            format: BinaryFormat::MachO,
            arch: arch.to_string(),
            universal: false,
        });
    }
    if (magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xca, 0xfe, 0xba, 0xbf]) && bytes.len() >= 8
    {
        let nfat = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if (1..20).contains(&nfat) {
            return Ok(BinaryInfo {
                format: BinaryFormat::MachO,
                arch: "universal".to_string(),
                universal: true,
            });
        }
    }

    // 3. PE/COFF (MZ + e_lfanew -> PE\0\0 + machine)
    if bytes.len() >= 64 && &bytes[0..2] == b"MZ" {
        let pe_off = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
        if pe_off + 6 <= bytes.len() && &bytes[pe_off..pe_off + 4] == b"PE\0\0" {
            let machine = u16::from_le_bytes([bytes[pe_off + 4], bytes[pe_off + 5]]);
            let arch = match machine {
                0x8664 => "x86_64",
                0xaa64 => "arm64",
                other => {
                    return Err(ArchiveError::InvalidBinary(format!(
                        "unsupported PE machine 0x{other:04x}"
                    )));
                }
            };
            return Ok(BinaryInfo {
                format: BinaryFormat::Pe,
                arch: arch.to_string(),
                universal: false,
            });
        }
    }

    Err(ArchiveError::InvalidBinary(
        "unrecognized ELF, Mach-O, or PE header".into(),
    ))
}

/// Atomically writes bytes via a same-directory temporary file with restricted permissions.
pub fn write_atomic(dest: &Path, bytes: &[u8], executable: bool) -> Result<(), ArchiveError> {
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut tmp = tempfile::Builder::new()
        .prefix(".sds-tmp-")
        .tempfile_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o755 } else { 0o600 };
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    tmp.persist(dest).map_err(|e| ArchiveError::Io(e.error))?;
    Ok(())
}

/// Downloads an HTTPS release artifact via `curl` (HTTPS-only, TLS >= 1.2) and verifies its SHA-256.
pub async fn download_https_verified(
    url: &str,
    dest: &Path,
    expected_sha256: &str,
    max_bytes: u64,
) -> Result<u64, ArchiveError> {
    let valid_url = validate_https_url(url)?;
    let expected = validate_sha256_hex(expected_sha256)?;
    let parent = dest
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "dest has no parent"))?;
    fs::create_dir_all(parent)?;
    let tmp = tempfile::Builder::new()
        .prefix(".sds-dl-")
        .tempfile_in(parent)?;
    let tmp_path = tmp.path().to_path_buf();
    let max_arg = max_bytes.to_string();

    let output = tokio::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            "15",
            "--max-time",
            "600",
            "--max-filesize",
            &max_arg,
            "-o",
        ])
        .arg(&tmp_path)
        .arg("--")
        .arg(&valid_url)
        .output()
        .await?;

    if !output.status.success() {
        return Err(ArchiveError::DownloadFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }
    let size = verify_archive_file(&tmp_path, &expected, max_bytes)?;
    tmp.persist(dest).map_err(|e| ArchiveError::Io(e.error))?;
    Ok(size)
}
