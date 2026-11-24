//! Strict input validators and safe quoting helpers for installer parameters and paths.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, PathBuf};
use thiserror::Error;

/// Errors returned when a user-supplied or manifest-supplied value violates safety constraints.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("value must not be empty")]
    Empty,
    #[error("value exceeds maximum allowed length of {0} bytes")]
    TooLong(usize),
    #[error("value contains forbidden whitespace or control characters")]
    ControlOrWhitespace,
    #[error("value starts with '-' which could be interpreted as a CLI option")]
    LeadingDash,
    #[error("invalid host or IP address: {0}")]
    InvalidHost(String),
    #[error("invalid IP address literal: {0}")]
    InvalidIpLiteral(String),
    #[error("invalid SSH target (expected user@host or host): {0}")]
    InvalidSshTarget(String),
    #[error("invalid X11 display (expected :1 through :99): {0}")]
    InvalidDisplay(String),
    #[error("invalid SHA-256 hex digest (expected 64 hex chars)")]
    InvalidSha256,
    #[error("invalid HTTPS URL: {0}")]
    InvalidHttpsUrl(String),
    #[error("unsafe or non-relative archive path: {0}")]
    UnsafeArchivePath(String),
    #[error("invalid instance name (expected lowercase [a-z0-9-], 1..32 chars): {0}")]
    InvalidInstanceName(String),
    #[error("invalid DRM render device path: {0}")]
    InvalidRenderDevice(String),
    #[error("invalid PIN (expected exactly 4 ASCII digits)")]
    InvalidPin,
    #[error("invalid port number (must be 1..=65535)")]
    InvalidPort,
    #[error("invalid resolution (expected WIDTHxHEIGHT between 640x480 and 7680x4320): {0}")]
    InvalidResolution(String),
    #[error("invalid macOS local signing identity (expected 40 hex chars)")]
    InvalidSigningIdentity,
}

fn check_basic_chars(raw: &str, max_len: usize) -> Result<&str, ValidationError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::Empty);
    }
    if trimmed.len() > max_len {
        return Err(ValidationError::TooLong(max_len));
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(ValidationError::ControlOrWhitespace);
    }
    if trimmed.starts_with('-') {
        return Err(ValidationError::LeadingDash);
    }
    Ok(trimmed)
}

/// Validates an IPv4/IPv6 literal or an RFC-1123 hostname (no schemes, ports, or shell chars).
pub fn validate_ip_or_host(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 253)?;
    let unbracketed = s
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(s);
    if unbracketed.parse::<IpAddr>().is_ok() {
        return Ok(unbracketed.to_string());
    }
    if s.contains('[') || s.contains(']') || s.contains(':') || s.contains('/') {
        return Err(ValidationError::InvalidHost(s.to_string()));
    }
    let host = s.strip_suffix('.').unwrap_or(s);
    if host.is_empty() || host.len() > 253 {
        return Err(ValidationError::InvalidHost(s.to_string()));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(ValidationError::InvalidHost(s.to_string()));
        }
    }
    Ok(host.to_string())
}

/// Validates an IPv4 or IPv6 literal suitable for strict host firewall rules.
pub fn validate_ipv4_or_ipv6_literal(raw: &str) -> Result<IpAddr, ValidationError> {
    let s = check_basic_chars(raw, 64)?;
    let unbracketed = s
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(s);
    let ip: IpAddr = unbracketed
        .parse()
        .map_err(|_| ValidationError::InvalidIpLiteral(s.to_string()))?;
    if ip.is_unspecified() || ip.is_multicast() {
        return Err(ValidationError::InvalidIpLiteral(s.to_string()));
    }
    Ok(ip)
}

/// Returns `true` when an IP address belongs to RFC1918/CGNAT/ULA/link-local/loopback space.
pub fn is_private_or_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        // Carrier-grade NAT / Tailscale 100.64.0.0/10
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        // RFC 5737 TEST-NETs commonly used in offline fixtures
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unique_local()
        || ((v6.segments()[0] & 0xffc0) == 0xfe80)
        || v6.to_ipv4_mapped().is_some_and(is_private_v4)
}

/// Validates an SSH destination (`user@host` or `host` alias) without CLI flags or metacharacters.
pub fn validate_ssh_target(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 255)?;
    if s.contains("..") || s.contains('/') || s.contains('\\') {
        return Err(ValidationError::InvalidSshTarget(s.to_string()));
    }
    let (user_part, host_part) = match s.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, s),
    };
    if let Some(u) = user_part {
        if u.is_empty()
            || u.len() > 64
            || u.starts_with('-')
            || !u
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(ValidationError::InvalidSshTarget(s.to_string()));
        }
    }
    let validated_host = validate_ip_or_host(host_part)
        .map_err(|_| ValidationError::InvalidSshTarget(s.to_string()))?;
    match user_part {
        Some(u) => Ok(format!("{u}@{validated_host}")),
        None => Ok(validated_host),
    }
}

/// Validates an isolated X11 display identifier (`:1`..`:99`, disallowing `:0`).
pub fn validate_x11_display(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 8)?;
    let num_str = s
        .strip_prefix(':')
        .ok_or_else(|| ValidationError::InvalidDisplay(s.to_string()))?;
    if num_str.is_empty() || num_str.len() > 2 || !num_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValidationError::InvalidDisplay(s.to_string()));
    }
    let num: u8 = num_str
        .parse()
        .map_err(|_| ValidationError::InvalidDisplay(s.to_string()))?;
    if !(1..=99).contains(&num) {
        return Err(ValidationError::InvalidDisplay(s.to_string()));
    }
    Ok(format!(":{num}"))
}

/// Validates a 64-character SHA-256 hex digest and returns it normalized to lowercase.
pub fn validate_sha256_hex(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 64)?;
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidSha256);
    }
    Ok(s.to_ascii_lowercase())
}

/// Validates an HTTPS URL (rejecting credentials in URL, whitespace, fragments, invalid ports, or non-HTTPS).
pub fn validate_https_url(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 2048)?;
    if s.contains('#') {
        return Err(ValidationError::InvalidHttpsUrl(s.to_string()));
    }
    let rest = s
        .strip_prefix("https://")
        .ok_or_else(|| ValidationError::InvalidHttpsUrl(s.to_string()))?;
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(ValidationError::InvalidHttpsUrl(s.to_string()));
    }
    let (host_only, port_opt) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let (addr, tail) = after_bracket
            .split_once(']')
            .ok_or_else(|| ValidationError::InvalidHttpsUrl(s.to_string()))?;
        let port = if tail.is_empty() {
            None
        } else if let Some(p) = tail.strip_prefix(':') {
            Some(p)
        } else {
            return Err(ValidationError::InvalidHttpsUrl(s.to_string()));
        };
        (addr, port)
    } else if let Some((h, p)) = authority.split_once(':') {
        if p.contains(':') {
            return Err(ValidationError::InvalidHttpsUrl(s.to_string()));
        }
        (h, Some(p))
    } else {
        (authority, None)
    };
    if let Some(p_str) = port_opt {
        let port: u16 = p_str
            .parse()
            .map_err(|_| ValidationError::InvalidHttpsUrl(s.to_string()))?;
        validate_port(port).map_err(|_| ValidationError::InvalidHttpsUrl(s.to_string()))?;
    }
    validate_ip_or_host(host_only).map_err(|_| ValidationError::InvalidHttpsUrl(s.to_string()))?;
    Ok(s.to_string())
}

/// Validates a relative path from an archive or manifest against traversal and Windows drive escapes.
pub fn validate_relative_archive_path(raw: &str) -> Result<PathBuf, ValidationError> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(ValidationError::UnsafeArchivePath(raw.to_string()));
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(ValidationError::UnsafeArchivePath(raw.to_string()));
    }
    // Reject Windows drive-letter prefixes such as "C:foo" or "C:/foo".
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(ValidationError::UnsafeArchivePath(raw.to_string()));
    }
    if raw.contains('\\') {
        return Err(ValidationError::UnsafeArchivePath(raw.to_string()));
    }
    let mut out = PathBuf::new();
    for segment in raw.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ValidationError::UnsafeArchivePath(raw.to_string()));
        }
        if segment.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(ValidationError::UnsafeArchivePath(raw.to_string()));
        }
        out.push(segment);
    }
    // Defense in depth: inspect std::path::Path components as well.
    for comp in out.components() {
        if !matches!(comp, Component::Normal(_)) {
            return Err(ValidationError::UnsafeArchivePath(raw.to_string()));
        }
    }
    Ok(out)
}

/// Validates an instance slug used for systemd units, config subdirectories, and audio sinks.
pub fn validate_instance_name(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 32)?;
    let valid_first = s
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !valid_first
        || !s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ValidationError::InvalidInstanceName(s.to_string()));
    }
    Ok(s.to_string())
}

/// Validates a Linux DRM render node path (`/dev/dri/renderD...` or `/dev/dri/by-path/...`).
pub fn validate_render_device(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 160)?;
    if s.contains("..") {
        return Err(ValidationError::InvalidRenderDevice(s.to_string()));
    }
    if let Some(num) = s.strip_prefix("/dev/dri/renderD") {
        if (1..=4).contains(&num.len()) && num.chars().all(|c| c.is_ascii_digit()) {
            return Ok(s.to_string());
        }
        return Err(ValidationError::InvalidRenderDevice(s.to_string()));
    }
    if let Some(suffix) = s.strip_prefix("/dev/dri/by-path/") {
        if !suffix.is_empty()
            && !suffix.contains('/')
            && suffix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
        {
            return Ok(s.to_string());
        }
    }
    Err(ValidationError::InvalidRenderDevice(s.to_string()))
}

/// Validates a 4-digit Moonlight pairing PIN.
pub fn validate_pin(raw: &str) -> Result<String, ValidationError> {
    let s = raw.trim();
    if s.len() != 4 || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValidationError::InvalidPin);
    }
    Ok(s.to_string())
}

/// Validates a TCP/UDP port number (`1..=65535`).
pub fn validate_port(port: u16) -> Result<u16, ValidationError> {
    if port == 0 {
        return Err(ValidationError::InvalidPort);
    }
    Ok(port)
}

/// Validates a screen resolution like `1920x1080`.
pub fn validate_resolution(raw: &str) -> Result<(u32, u32), ValidationError> {
    let s = check_basic_chars(raw, 16)?;
    let (w_str, h_str) = s
        .split_once('x')
        .ok_or_else(|| ValidationError::InvalidResolution(s.to_string()))?;
    let w: u32 = w_str
        .parse()
        .map_err(|_| ValidationError::InvalidResolution(s.to_string()))?;
    let h: u32 = h_str
        .parse()
        .map_err(|_| ValidationError::InvalidResolution(s.to_string()))?;
    if !(640..=7680).contains(&w) || !(480..=4320).contains(&h) {
        return Err(ValidationError::InvalidResolution(s.to_string()));
    }
    Ok((w, h))
}

/// Validates a 40-digit SHA-1 fingerprint for macOS local code signing.
pub fn validate_signing_identity(raw: &str) -> Result<String, ValidationError> {
    let s = check_basic_chars(raw, 40)?;
    if s.len() != 40 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidSigningIdentity);
    }
    Ok(s.to_ascii_uppercase())
}

/// Quotes a string safely for POSIX `/bin/sh` single-quoted arguments.
pub fn shell_single_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\"'\"'");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Constant-time comparison of two strings (e.g. SHA-256 digests, auth codes, CSRF tokens).
pub fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    aws_lc_rs::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_ssh_validators_reject_injection_and_flags() {
        assert_eq!(validate_ip_or_host("192.168.1.50").unwrap(), "192.168.1.50");
        assert_eq!(validate_ip_or_host("[::1]").unwrap(), "::1");
        assert_eq!(
            validate_ssh_target("alice@host.local").unwrap(),
            "alice@host.local"
        );
        assert!(validate_ssh_target("-oProxyCommand=id").is_err());
        assert!(validate_ssh_target("alice@host;rm -rf /").is_err());
        assert!(validate_ssh_target("alice@host$(id)").is_err());
        assert!(validate_ip_or_host("host:47984").is_err());
    }

    #[test]
    fn archive_paths_reject_traversal_and_drives() {
        assert_eq!(
            validate_relative_archive_path("bin/sds-installer").unwrap(),
            PathBuf::from("bin/sds-installer")
        );
        assert!(validate_relative_archive_path("../evil").is_err());
        assert!(validate_relative_archive_path("a/../b").is_err());
        assert!(validate_relative_archive_path("/etc/passwd").is_err());
        assert!(validate_relative_archive_path(r"C:\Windows\win.ini").is_err());
        assert!(validate_relative_archive_path("C:foo").is_err());
        assert!(validate_relative_archive_path("a\\b").is_err());
    }

    #[test]
    fn display_and_constant_time_work() {
        assert_eq!(validate_x11_display(":97").unwrap(), ":97");
        assert!(validate_x11_display(":0").is_err());
        assert!(validate_x11_display(":100").is_err());
        assert!(constant_time_hex_eq("abcd", "abcd"));
        assert!(!constant_time_hex_eq("abcd", "abce"));
        assert!(!constant_time_hex_eq("abcd", "abc"));
        assert_eq!(shell_single_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn https_url_validates_ports_and_rejects_fragments() {
        assert_eq!(
            validate_https_url("https://example.com:8443/path?a=1").unwrap(),
            "https://example.com:8443/path?a=1"
        );
        assert_eq!(
            validate_https_url("https://[::1]:443/x").unwrap(),
            "https://[::1]:443/x"
        );
        assert!(validate_https_url("https://example.com/release#frag").is_err());
        assert!(validate_https_url("https://example.com:0/release").is_err());
        assert!(validate_https_url("https://example.com:99999/release").is_err());
        assert!(validate_https_url("https://example.com:abc/release").is_err());
        assert!(validate_https_url("https://[::1/release").is_err());
        assert!(validate_https_url("http://example.com/release").is_err());
    }
}
