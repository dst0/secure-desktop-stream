//! Cryptographic host verification engine:
//! - Enforces and probes PQ TLS 1.3 (`X25519MLKEM768`) on 47984/tcp
//! - Verifies classical KEX (`X25519` / `SECP256R1`) and TLS 1.2 are rejected
//! - Checks firewall exposure of 47989/tcp (pairing HTTP), 47990/tcp (admin UI), 48010/tcp (RTSP)
//! - Compares live TLS certificate SHA-256 against out-of-band PQ SSH certificate fingerprint

use crate::validation::{
    constant_time_hex_eq, is_private_or_loopback_ip, shell_single_quote, validate_ip_or_host,
    validate_port, validate_ssh_target,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio_rustls::TlsConnector;

const TCP_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_TIMEOUT: Duration = Duration::from_secs(4);
const SSH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProbeRequest {
    pub host: String,
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_webui_port")]
    pub webui_port: u16,
    #[serde(default = "default_rtsp_port")]
    pub rtsp_port: u16,
    #[serde(default)]
    pub ssh_target: Option<String>,
    #[serde(default = "default_true")]
    pub require_pq_ssh: bool,
    #[serde(default)]
    pub strict_ssh_host_key: bool,
    #[serde(default)]
    pub ssh_cert_path: Option<String>,
}

fn default_https_port() -> u16 {
    47984
}
fn default_http_port() -> u16 {
    47989
}
fn default_webui_port() -> u16 {
    47990
}
fn default_rtsp_port() -> u16 {
    48010
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostProbeVerdict {
    ReadyHardened,
    ReadyNeedsPairingLockdown,
    InsecureConfiguration,
    HostNotInstalledOrUnreachable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshFingerprintStatus {
    Matched,
    Mismatch,
    CertNotFound,
    CertFetchedPortClosed,
    SshFailed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeFinding {
    pub severity: String, // "ok" | "warning" | "critical"
    pub code: String,
    pub message_ru: String,
    pub message_en: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProbeReport {
    pub host: String,
    pub public_ip_warning: bool,
    pub https_port_open: bool,
    pub pq_tls13_ok: bool,
    pub mtls_client_auth_required: bool,
    pub negotiated_kx_group: Option<String>,
    pub negotiated_tls_version: Option<String>,
    pub classical_kex_rejected: bool,
    pub tls12_rejected: bool,
    pub port_47989_http_open: bool,
    pub port_47990_webui_open: bool,
    pub port_48010_rtsp_open: bool,
    pub cert_sha256_hex: Option<String>,
    pub cert_sha256_fingerprint: Option<String>,
    pub ssh_fingerprint_status: SshFingerprintStatus,
    pub ssh_cert_sha256_hex: Option<String>,
    pub ssh_detail: Option<String>,
    pub verdict: HostProbeVerdict,
    pub findings: Vec<ProbeFinding>,
    pub notes: Vec<String>,
}

#[derive(Debug)]
struct CapturingServerCertVerifier {
    algs: WebPkiSupportedAlgorithms,
    allow_tls12_sig: bool,
    captured_der: Arc<Mutex<Option<Vec<u8>>>>,
    sig_verified: Arc<AtomicBool>,
}

impl CapturingServerCertVerifier {
    fn new(algs: WebPkiSupportedAlgorithms, allow_tls12_sig: bool) -> Self {
        Self {
            algs,
            allow_tls12_sig,
            captured_der: Arc::new(Mutex::new(None)),
            sig_verified: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ServerCertVerifier for CapturingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref().is_empty() {
            return Err(TlsError::NoCertificatesPresented);
        }
        let _ = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if let Ok(mut guard) = self.captured_der.lock() {
            *guard = Some(end_entity.as_ref().to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if !self.allow_tls12_sig {
            return Err(TlsError::General("TLS 1.2 is forbidden on PQ probe".into()));
        }
        let res = verify_tls12_signature(message, cert, dss, &self.algs)?;
        self.sig_verified.store(true, Ordering::SeqCst);
        Ok(res)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let res = verify_tls13_signature(message, cert, dss, &self.algs)?;
        self.sig_verified.store(true, Ordering::SeqCst);
        Ok(res)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Computes lowercase hex SHA-256 of DER-encoded certificate bytes.
pub fn sha256_der_hex(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

/// Formats a 64-char hex digest as uppercase colon-separated fingerprint bytes.
pub fn format_sha256_colon(hex_digest: &str) -> String {
    let upper = hex_digest.to_ascii_uppercase();
    upper
        .as_bytes()
        .chunks(2)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect::<Vec<_>>()
        .join(":")
}

/// Generates an ephemeral in-memory client certificate + private key for probe handshakes.
pub fn generate_ephemeral_client_identity(
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert = rcgen::generate_simple_self_signed(vec!["sds-probe.local".to_string()])
        .map_err(|e| format!("failed to generate ephemeral probe client cert: {e}"))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    Ok((vec![cert_der], key_der))
}

fn server_name_for(host: &str) -> Result<ServerName<'static>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_string())
            .map_err(|e| format!("invalid TLS server name '{host}': {e}"))
    }
}

async fn check_tcp_open(host: &str, port: u16) -> bool {
    let addr = format_host_port(host, port);
    tokio::time::timeout(TCP_TIMEOUT, TcpStream::connect(&addr))
        .await
        .is_ok_and(|res| res.is_ok())
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[derive(Debug)]
struct TlsProbeOutcome {
    handshake_completed: bool,
    client_cert_rejected_alert: bool,
    server_sig_verified: bool,
    captured_der: Option<Vec<u8>>,
    negotiated_kx: Option<String>,
    negotiated_version: Option<String>,
    error_note: Option<String>,
}

fn empty_outcome(error_note: impl Into<String>) -> TlsProbeOutcome {
    TlsProbeOutcome {
        handshake_completed: false,
        client_cert_rejected_alert: false,
        server_sig_verified: false,
        captured_der: None,
        negotiated_kx: None,
        negotiated_version: None,
        error_note: Some(error_note.into()),
    }
}

async fn run_tls_probe(
    host: &str,
    port: u16,
    provider: Arc<CryptoProvider>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    allow_tls12_sig: bool,
) -> TlsProbeOutcome {
    let addr = format_host_port(host, port);
    let tcp = match tokio::time::timeout(TCP_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return empty_outcome(format!("TCP connect error: {e}")),
        Err(_) => return empty_outcome("TCP connect timed out"),
    };

    let verifier = Arc::new(CapturingServerCertVerifier::new(
        provider.signature_verification_algorithms,
        allow_tls12_sig,
    ));
    let (client_certs, client_key) = match generate_ephemeral_client_identity() {
        Ok(id) => id,
        Err(e) => return empty_outcome(e),
    };
    let builder =
        match ClientConfig::builder_with_provider(provider).with_protocol_versions(versions) {
            Ok(b) => b,
            Err(e) => return empty_outcome(format!("TLS config builder error: {e}")),
        };
    let config = match builder
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_auth_cert(client_certs, client_key)
    {
        Ok(c) => Arc::new(c),
        Err(e) => return empty_outcome(format!("TLS client auth config error: {e}")),
    };
    let sname = match server_name_for(host) {
        Ok(n) => n,
        Err(e) => return empty_outcome(e),
    };

    let connector = TlsConnector::from(config);
    match tokio::time::timeout(TLS_TIMEOUT, connector.connect(sname, tcp)).await {
        Ok(Ok(mut tls)) => {
            let (_, conn) = tls.get_ref();
            let negotiated_kx = conn
                .negotiated_key_exchange_group()
                .map(|g| format!("{:?}", g.name()));
            let negotiated_version = conn.protocol_version().map(|v| format!("{v:?}"));
            // In TLS 1.3, server-side client-cert rejection alerts arrive right after client Finished
            // (during the first post-handshake read), so briefly poll for a TLS alert.
            let mut probe_buf = [0u8; 1];
            let client_cert_rejected_alert = matches!(
                tokio::time::timeout(Duration::from_millis(150), tls.read(&mut probe_buf)).await,
                Ok(Err(ref e))
                    if e.kind() == std::io::ErrorKind::InvalidData
                        || e.to_string().contains("AlertReceived")
            );
            TlsProbeOutcome {
                handshake_completed: true,
                client_cert_rejected_alert,
                server_sig_verified: verifier.sig_verified.load(Ordering::SeqCst),
                captured_der: verifier.captured_der.lock().ok().and_then(|g| g.clone()),
                negotiated_kx,
                negotiated_version,
                error_note: None,
            }
        }
        Ok(Err(e)) => TlsProbeOutcome {
            handshake_completed: false,
            client_cert_rejected_alert: false,
            server_sig_verified: verifier.sig_verified.load(Ordering::SeqCst),
            captured_der: verifier.captured_der.lock().ok().and_then(|g| g.clone()),
            negotiated_kx: None,
            negotiated_version: None,
            error_note: Some(format!("TLS handshake rejected: {e}")),
        },
        Err(_) => TlsProbeOutcome {
            handshake_completed: false,
            client_cert_rejected_alert: false,
            server_sig_verified: verifier.sig_verified.load(Ordering::SeqCst),
            captured_der: verifier.captured_der.lock().ok().and_then(|g| g.clone()),
            negotiated_kx: None,
            negotiated_version: None,
            error_note: Some("TLS handshake timed out".into()),
        },
    }
}

fn pq_only_provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites = vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    Arc::new(provider)
}

fn classical_only_provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    ];
    provider.cipher_suites = vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ];
    Arc::new(provider)
}

fn tls12_provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![
        rustls::crypto::aws_lc_rs::kx_group::X25519,
        rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
    ];
    provider.cipher_suites = vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ];
    Arc::new(provider)
}

/// Fetches the public Sunshine `cacert.pem` over SSH (optionally enforcing PQ KEX) and returns SHA-256 hex.
pub async fn fetch_remote_cert_sha256_via_ssh(
    ssh_target: &str,
    require_pq_ssh: bool,
    strict_host_key: bool,
    explicit_cert_path: Option<&str>,
) -> Result<String, (SshFingerprintStatus, String)> {
    let target = validate_ssh_target(ssh_target)
        .map_err(|e| (SshFingerprintStatus::SshFailed, e.to_string()))?;

    let mut args = vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=8".to_string(),
        "-o".to_string(),
        format!(
            "StrictHostKeyChecking={}",
            if strict_host_key { "yes" } else { "accept-new" }
        ),
    ];
    if require_pq_ssh {
        args.push("-o".to_string());
        args.push("KexAlgorithms=mlkem768x25519-sha256".to_string());
    }
    args.push("--".to_string());
    args.push(target);

    let remote_script = if let Some(custom) = explicit_cert_path {
        let trimmed = custom.trim();
        if trimmed.is_empty()
            || trimmed.contains('\0')
            || !trimmed.ends_with(".pem")
            || trimmed.contains("..")
        {
            return Err((
                SshFingerprintStatus::SshFailed,
                "invalid remote certificate path".into(),
            ));
        }
        if let Some(rest) = trimmed.strip_prefix("~/") {
            if rest.is_empty() {
                return Err((
                    SshFingerprintStatus::SshFailed,
                    "invalid remote certificate path".into(),
                ));
            }
            format!(
                "f=\"$HOME\"/{}; [ -f \"$f\" ] && cat \"$f\" || exit 42",
                shell_single_quote(rest)
            )
        } else {
            format!(
                "f={}; [ -f \"$f\" ] && cat \"$f\" || exit 42",
                shell_single_quote(trimmed)
            )
        }
    } else {
        // Check standard Secure Desktop Stream and Sunshine public cert paths (never cakey.pem).
        concat!(
            "for f in ",
            "\"$HOME/.config/sds-host-sunshine/config/sunshine/credentials/cacert.pem\" ",
            "\"$HOME/.config/\"*-sunshine/config/sunshine/credentials/cacert.pem ",
            "\"$HOME/.config/sunshine/credentials/cacert.pem\" ",
            "/etc/sunshine/cacert.pem; ",
            "do if [ -f \"$f\" ]; then cat \"$f\"; exit 0; fi; done; exit 42"
        )
        .to_string()
    };
    args.push(remote_script);

    let output = tokio::time::timeout(
        SSH_TIMEOUT,
        Command::new("ssh")
            .args(&args)
            .stdin(std::process::Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| {
        (
            SshFingerprintStatus::SshFailed,
            "SSH command timed out".to_string(),
        )
    })?
    .map_err(|e| {
        (
            SshFingerprintStatus::SshFailed,
            format!("failed to spawn ssh: {e}"),
        )
    })?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if code == 42 {
            return Err((
                SshFingerprintStatus::CertNotFound,
                "Sunshine cacert.pem was not found on remote host".into(),
            ));
        }
        return Err((
            SshFingerprintStatus::SshFailed,
            if stderr.is_empty() {
                format!("ssh exited with code {code}")
            } else {
                stderr
            },
        ));
    }

    let mut reader = BufReader::new(output.stdout.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                SshFingerprintStatus::CertNotFound,
                format!("invalid PEM from host: {e}"),
            )
        })?;
    let first = certs.first().ok_or_else(|| {
        (
            SshFingerprintStatus::CertNotFound,
            "remote cacert.pem contained no certificates".to_string(),
        )
    })?;
    Ok(sha256_der_hex(first.as_ref()))
}

/// Runs a full cryptographic + firewall hygiene probe against a Sunshine host.
pub async fn probe_host(req: &HostProbeRequest) -> Result<HostProbeReport, String> {
    let host = validate_ip_or_host(&req.host).map_err(|e| e.to_string())?;
    let https_port = validate_port(req.https_port).map_err(|e| e.to_string())?;
    let http_port = validate_port(req.http_port).map_err(|e| e.to_string())?;
    let webui_port = validate_port(req.webui_port).map_err(|e| e.to_string())?;
    let rtsp_port = validate_port(req.rtsp_port).map_err(|e| e.to_string())?;

    let public_ip_warning = host
        .parse::<IpAddr>()
        .is_ok_and(|ip| !is_private_or_loopback_ip(ip));

    let mut findings = Vec::new();
    let mut notes = Vec::new();
    if public_ip_warning {
        findings.push(ProbeFinding {
            severity: "warning".into(),
            code: "public_ip_target".into(),
            message_ru: "Целевой адрес не относится к частным LAN/VPN подсетям — Secure Desktop Stream предназначен только для LAN/VPN.".into(),
            message_en: "Target IP is not in private LAN/VPN space; Secure Desktop Stream is designed for LAN/VPN only.".into(),
        });
    }

    let https_port_open = check_tcp_open(&host, https_port).await;
    let port_47989_http_open = check_tcp_open(&host, http_port).await;
    let port_47990_webui_open = check_tcp_open(&host, webui_port).await;
    let port_48010_rtsp_open = check_tcp_open(&host, rtsp_port).await;

    if !https_port_open {
        let mut ssh_fingerprint_status = SshFingerprintStatus::Skipped;
        let mut ssh_cert_sha256_hex = None;
        let mut ssh_detail = None;
        if let Some(ref ssh) = req.ssh_target {
            if !ssh.trim().is_empty() {
                match fetch_remote_cert_sha256_via_ssh(
                    ssh,
                    req.require_pq_ssh,
                    req.strict_ssh_host_key,
                    req.ssh_cert_path.as_deref(),
                )
                .await
                {
                    Ok(digest) => {
                        ssh_fingerprint_status = SshFingerprintStatus::CertFetchedPortClosed;
                        ssh_cert_sha256_hex = Some(digest);
                        ssh_detail = Some(
                            "Certificate file exists over SSH, but HTTPS port is closed/stopped"
                                .into(),
                        );
                    }
                    Err((status, msg)) => {
                        ssh_fingerprint_status = status;
                        ssh_detail = Some(msg);
                    }
                }
            }
        }
        findings.push(ProbeFinding {
            severity: "critical".into(),
            code: "https_unreachable".into(),
            message_ru: format!("Порт {https_port}/tcp недоступен — сервер Sunshine не установлен, остановлен или закрыт файрволом."),
            message_en: format!("Port {https_port}/tcp is unreachable — Sunshine is not installed, not running, or blocked by firewall."),
        });
        return Ok(HostProbeReport {
            host,
            public_ip_warning,
            https_port_open: false,
            pq_tls13_ok: false,
            mtls_client_auth_required: false,
            negotiated_kx_group: None,
            negotiated_tls_version: None,
            classical_kex_rejected: false,
            tls12_rejected: false,
            port_47989_http_open,
            port_47990_webui_open,
            port_48010_rtsp_open,
            cert_sha256_hex: None,
            cert_sha256_fingerprint: None,
            ssh_fingerprint_status,
            ssh_cert_sha256_hex,
            ssh_detail,
            verdict: HostProbeVerdict::HostNotInstalledOrUnreachable,
            findings,
            notes,
        });
    }

    // 1. Positive PQ TLS 1.3 probe (X25519MLKEM768 only)
    let pq = run_tls_probe(
        &host,
        https_port,
        pq_only_provider(),
        &[&rustls::version::TLS13],
        false,
    )
    .await;
    if let Some(ref e) = pq.error_note {
        notes.push(format!("PQ probe: {e}"));
    }

    let pq_tls13_ok = if pq.handshake_completed {
        let kx_ok = pq
            .negotiated_kx
            .as_deref()
            .is_some_and(|k| k.contains("X25519MLKEM768") || k.contains("MlKem"));
        let ver_ok = pq
            .negotiated_version
            .as_deref()
            .is_some_and(|v| v.contains("TLSv1_3"));
        kx_ok && ver_ok && pq.server_sig_verified
    } else {
        // If server aborted strictly on mTLS client cert verification AFTER completing ServerHello(X25519MLKEM768)
        // and cryptographically verifying its own TLS 1.3 CertificateVerify signature:
        pq.server_sig_verified && pq.captured_der.is_some()
    };

    let mtls_client_auth_required =
        pq.client_cert_rejected_alert || (!pq.handshake_completed && pq.server_sig_verified);
    let negotiated_kx_group = pq.negotiated_kx.or_else(|| {
        if pq_tls13_ok {
            Some("X25519MLKEM768".to_string())
        } else {
            None
        }
    });
    let negotiated_tls_version = pq.negotiated_version.or_else(|| {
        if pq_tls13_ok {
            Some("TLSv1_3".to_string())
        } else {
            None
        }
    });

    let cert_sha256_hex = pq.captured_der.as_deref().map(sha256_der_hex);
    let cert_sha256_fingerprint = cert_sha256_hex.as_deref().map(format_sha256_colon);

    if pq_tls13_ok {
        findings.push(ProbeFinding {
            severity: "ok".into(),
            code: "pq_tls13_verified".into(),
            message_ru: "Подтверждён TLS 1.3 + постквантовый обмен ключами X25519MLKEM768.".into(),
            message_en: "Verified TLS 1.3 + post-quantum X25519MLKEM768 key exchange.".into(),
        });
    } else {
        findings.push(ProbeFinding {
            severity: "critical".into(),
            code: "pq_tls13_failed".into(),
            message_ru: "Сервер не поддерживает TLS 1.3 с X25519MLKEM768 (возможно, это обычный upstream Sunshine без патча).".into(),
            message_en: "Server did not negotiate TLS 1.3 with X25519MLKEM768 (may be unhardened upstream Sunshine).".into(),
        });
    }

    // 2. Negative probe: classical KEX only (X25519 / P-256)
    let classical = run_tls_probe(
        &host,
        https_port,
        classical_only_provider(),
        &[&rustls::version::TLS13],
        false,
    )
    .await;
    if let Some(ref e) = classical.error_note {
        notes.push(format!("Classical negative probe: {e}"));
    }
    let classical_kex_rejected = !classical.handshake_completed && !classical.server_sig_verified;
    if classical_kex_rejected {
        findings.push(ProbeFinding {
            severity: "ok".into(),
            code: "classical_kex_rejected".into(),
            message_ru: "Классический обмен ключами (X25519 / P-256) отвергнут сервером.".into(),
            message_en: "Classical key exchange (X25519 / P-256) was strictly rejected by server."
                .into(),
        });
    } else {
        findings.push(ProbeFinding {
            severity: "critical".into(),
            code: "classical_kex_accepted".into(),
            message_ru: "ОПАСНО: сервер принимает классические группы X25519/P-256 без постквантового обмена!".into(),
            message_en: "INSECURE: server accepted classical X25519/P-256 key exchange without PQ!".into(),
        });
    }

    // 3. Negative probe: TLS 1.2
    let tls12 = run_tls_probe(
        &host,
        https_port,
        tls12_provider(),
        &[&rustls::version::TLS12],
        true,
    )
    .await;
    if let Some(ref e) = tls12.error_note {
        notes.push(format!("TLS 1.2 negative probe: {e}"));
    }
    let tls12_rejected = !tls12.handshake_completed && !tls12.server_sig_verified;
    if tls12_rejected {
        findings.push(ProbeFinding {
            severity: "ok".into(),
            code: "tls12_rejected".into(),
            message_ru: "Устаревший TLS 1.2 отвергнут сервером.".into(),
            message_en: "Legacy TLS 1.2 was rejected by server.".into(),
        });
    } else {
        findings.push(ProbeFinding {
            severity: "critical".into(),
            code: "tls12_accepted".into(),
            message_ru: "ОПАСНО: сервер принимает TLS 1.2!".into(),
            message_en: "INSECURE: server accepted legacy TLS 1.2!".into(),
        });
    }

    // 4. Web UI & HTTP port exposure checks
    if port_47990_webui_open {
        findings.push(ProbeFinding {
            severity: "critical".into(),
            code: "webui_exposed".into(),
            message_ru: format!("КРИТИЧНО: порт веб-админки {webui_port}/tcp доступен по сети! Он должен слушать/пробрасываться только через SSH-туннель 127.0.0.1:{webui_port}."),
            message_en: format!("CRITICAL: Admin Web UI port {webui_port}/tcp is reachable over the network! Bind loopback only and close firewall."),
        });
    } else {
        findings.push(ProbeFinding {
            severity: "ok".into(),
            code: "webui_closed".into(),
            message_ru: format!("Порт веб-админки {webui_port}/tcp закрыт снаружи."),
            message_en: format!("Admin Web UI port {webui_port}/tcp is closed externally."),
        });
    }

    if port_47989_http_open {
        findings.push(ProbeFinding {
            severity: "warning".into(),
            code: "http_47989_open".into(),
            message_ru: format!("Открыт HTTP-порт {http_port}/tcp. Оставьте его открытым только на время первичного пейринга, затем закройте в файрволе."),
            message_en: format!("Plain HTTP port {http_port}/tcp is open. Close it in the firewall after initial pairing."),
        });
    }

    // 5. Out-of-band PQ SSH fingerprint comparison
    let mut ssh_fingerprint_status = SshFingerprintStatus::Skipped;
    let mut ssh_cert_sha256_hex = None;
    let mut ssh_detail = None;
    if let Some(ref ssh) = req.ssh_target {
        if !ssh.trim().is_empty() {
            match fetch_remote_cert_sha256_via_ssh(
                ssh,
                req.require_pq_ssh,
                req.strict_ssh_host_key,
                req.ssh_cert_path.as_deref(),
            )
            .await
            {
                Ok(remote_hex) => {
                    ssh_cert_sha256_hex = Some(remote_hex.clone());
                    if let Some(ref live_hex) = cert_sha256_hex {
                        if constant_time_hex_eq(live_hex, &remote_hex) {
                            ssh_fingerprint_status = SshFingerprintStatus::Matched;
                            findings.push(ProbeFinding {
                                severity: "ok".into(),
                                code: "ssh_cert_match".into(),
                                message_ru: "Отпечаток сертификата по PQ TLS совпал с сертификатом, прочитанным по SSH (MITM исключён).".into(),
                                message_en: "Live TLS certificate SHA-256 matches the certificate fetched over SSH.".into(),
                            });
                        } else {
                            ssh_fingerprint_status = SshFingerprintStatus::Mismatch;
                            findings.push(ProbeFinding {
                                severity: "critical".into(),
                                code: "ssh_cert_mismatch".into(),
                                message_ru: "КРИТИЧНО: отпечаток сертификата по сети НЕ совпадает с сертификатом хоста по SSH! Возможен MITM или неверный хост.".into(),
                                message_en: "CRITICAL: TLS certificate fingerprint does NOT match SSH certificate on host! Possible MITM.".into(),
                            });
                        }
                    } else {
                        ssh_fingerprint_status = SshFingerprintStatus::SshFailed;
                        ssh_detail =
                            Some("No live TLS leaf certificate captured to compare".into());
                    }
                }
                Err((status, msg)) => {
                    ssh_fingerprint_status = status;
                    ssh_detail = Some(msg.clone());
                    findings.push(ProbeFinding {
                        severity: "warning".into(),
                        code: "ssh_fingerprint_unavailable".into(),
                        message_ru: format!("Не удалось проверить сертификат по SSH: {msg}"),
                        message_en: format!("Could not verify certificate over SSH: {msg}"),
                    });
                }
            }
        }
    }

    let verdict = if !pq_tls13_ok
        || !classical_kex_rejected
        || !tls12_rejected
        || port_47990_webui_open
        || ssh_fingerprint_status == SshFingerprintStatus::Mismatch
    {
        HostProbeVerdict::InsecureConfiguration
    } else if port_47989_http_open {
        HostProbeVerdict::ReadyNeedsPairingLockdown
    } else {
        HostProbeVerdict::ReadyHardened
    };

    Ok(HostProbeReport {
        host,
        public_ip_warning,
        https_port_open,
        pq_tls13_ok,
        mtls_client_auth_required,
        negotiated_kx_group,
        negotiated_tls_version,
        classical_kex_rejected,
        tls12_rejected,
        port_47989_http_open,
        port_47990_webui_open,
        port_48010_rtsp_open,
        cert_sha256_hex,
        cert_sha256_fingerprint,
        ssh_fingerprint_status,
        ssh_cert_sha256_hex,
        ssh_detail,
        verdict,
        findings,
        notes,
    })
}
