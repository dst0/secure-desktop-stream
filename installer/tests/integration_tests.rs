use flate2::write::GzEncoder;
use flate2::Compression;
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig, SignatureScheme,
};
use sds_installer::archive::{
    compute_file_sha256, detect_archive_kind, extract_tar_gz_safe, extract_zip_safe,
    parse_binary_header_bytes, parse_linux_text_manifest, parse_release_manifest_json,
    verify_archive_file, ArchiveKind, BinaryFormat, ExtractionLimits,
};
use sds_installer::config_gen::{
    generate_firewall_commands, generate_host_bundle, EncoderKind, FirewallBackend,
    HostConfigParams, HostProfileKind,
};
use sds_installer::deps::{check_dependencies, DependencyCheckRequest, DependencyRole};
use sds_installer::installer_ops::{decode_chunked_bytes, ProgressEmitter};
use sds_installer::probe::{probe_host, sha256_der_hex, HostProbeRequest, HostProbeVerdict};
use sds_installer::tui::{render_tui_frame, TuiApp};
use sds_installer::ui_state::{
    select_ui_launch_mode, ClientFormState, ClientSourceKind, HostFormState, PendingConfirmation,
    ProbePairFormState, UiLaunchMode, UiTab,
};
use sds_installer::uninstall::{
    is_safe_sds_removal_path, load_manifest, record_client_install, record_host_install,
    run_uninstall_for_home, HostManifestEntry, UninstallComponent, UninstallRequest,
};
use sds_installer::validation::validate_https_url;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, TcpListener as StdTcpListener};
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[derive(Debug, Clone, Copy)]
enum MockTlsMode {
    PqOnlyAcceptAnyCert,
    PqOnlyRejectClientCert,
    ClassicalOnly,
    Tls12Only,
}

#[derive(Debug)]
struct MockClientVerifier {
    algs: WebPkiSupportedAlgorithms,
    reject_cert: bool,
}

impl ClientCertVerifier for MockClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if self.reject_cert {
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        } else {
            Ok(ClientCertVerified::assertion())
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

async fn spawn_mock_tls_server(mode: MockTlsMode) -> (u16, String, tokio::task::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let cert_sha = sha256_der_hex(cert_der.as_ref());
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let (versions, reject_client): (&[&rustls::SupportedProtocolVersion], bool) = match mode {
        MockTlsMode::PqOnlyAcceptAnyCert => {
            provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
            provider.cipher_suites = vec![
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
            (&[&rustls::version::TLS13], false)
        }
        MockTlsMode::PqOnlyRejectClientCert => {
            provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
            provider.cipher_suites = vec![
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
            (&[&rustls::version::TLS13], true)
        }
        MockTlsMode::ClassicalOnly => {
            provider.kx_groups = vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519,
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            ];
            provider.cipher_suites = vec![
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            ];
            (&[&rustls::version::TLS13], false)
        }
        MockTlsMode::Tls12Only => {
            provider.kx_groups = vec![
                rustls::crypto::aws_lc_rs::kx_group::X25519,
                rustls::crypto::aws_lc_rs::kx_group::SECP256R1,
            ];
            provider.cipher_suites = vec![
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ];
            (&[&rustls::version::TLS12], false)
        }
    };

    let provider = Arc::new(provider);
    let verifier = Arc::new(MockClientVerifier {
        algs: provider.signature_verification_algorithms,
        reject_cert: reject_client,
    });
    let cfg = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert_der], key_der)
            .unwrap(),
    );

    let acceptor = TlsAcceptor::from(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                break;
            };
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let _ = acc.accept(sock).await;
            });
        }
    });
    (port, cert_sha, handle)
}

fn alloc_closed_port() -> u16 {
    let l = StdTcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
async fn probe_accepts_hardened_pq_server_and_rejects_downgrades() {
    let (pq_port, expected_sha, h1) = spawn_mock_tls_server(MockTlsMode::PqOnlyAcceptAnyCert).await;
    let c1 = alloc_closed_port();
    let c2 = alloc_closed_port();
    let c3 = alloc_closed_port();

    let rep = probe_host(&HostProbeRequest {
        host: "127.0.0.1".into(),
        https_port: pq_port,
        http_port: c1,
        webui_port: c2,
        rtsp_port: c3,
        ssh_target: None,
        require_pq_ssh: false,
        strict_ssh_host_key: false,
        ssh_cert_path: None,
    })
    .await
    .unwrap();

    assert!(rep.https_port_open);
    assert!(rep.pq_tls13_ok);
    assert!(rep.classical_kex_rejected);
    assert!(rep.tls12_rejected);
    assert!(!rep.port_47989_http_open);
    assert!(!rep.port_47990_webui_open);
    assert_eq!(rep.cert_sha256_hex.as_deref(), Some(expected_sha.as_str()));
    assert_eq!(rep.verdict, HostProbeVerdict::ReadyHardened);
    h1.abort();

    // Verify strict mTLS rejection after PQ ServerHello still extracts verified cert fingerprint.
    let (pq_strict_port, strict_sha, h2) =
        spawn_mock_tls_server(MockTlsMode::PqOnlyRejectClientCert).await;
    let rep_strict = probe_host(&HostProbeRequest {
        host: "127.0.0.1".into(),
        https_port: pq_strict_port,
        http_port: alloc_closed_port(),
        webui_port: alloc_closed_port(),
        rtsp_port: alloc_closed_port(),
        ssh_target: None,
        require_pq_ssh: false,
        strict_ssh_host_key: false,
        ssh_cert_path: None,
    })
    .await
    .unwrap();
    assert!(rep_strict.pq_tls13_ok);
    assert!(rep_strict.mtls_client_auth_required);
    assert_eq!(
        rep_strict.cert_sha256_hex.as_deref(),
        Some(strict_sha.as_str())
    );
    assert_eq!(rep_strict.verdict, HostProbeVerdict::ReadyHardened);
    h2.abort();
}

#[tokio::test]
async fn probe_detects_insecure_classical_tls12_and_exposed_ports() {
    let (classical_port, _, h1) = spawn_mock_tls_server(MockTlsMode::ClassicalOnly).await;
    let rep_classical = probe_host(&HostProbeRequest {
        host: "127.0.0.1".into(),
        https_port: classical_port,
        http_port: alloc_closed_port(),
        webui_port: alloc_closed_port(),
        rtsp_port: alloc_closed_port(),
        ssh_target: None,
        require_pq_ssh: false,
        strict_ssh_host_key: false,
        ssh_cert_path: None,
    })
    .await
    .unwrap();
    assert!(!rep_classical.pq_tls13_ok);
    assert!(!rep_classical.classical_kex_rejected);
    assert_eq!(
        rep_classical.verdict,
        HostProbeVerdict::InsecureConfiguration
    );
    h1.abort();

    let (tls12_port, _, h2) = spawn_mock_tls_server(MockTlsMode::Tls12Only).await;
    let rep_tls12 = probe_host(&HostProbeRequest {
        host: "127.0.0.1".into(),
        https_port: tls12_port,
        http_port: alloc_closed_port(),
        webui_port: alloc_closed_port(),
        rtsp_port: alloc_closed_port(),
        ssh_target: None,
        require_pq_ssh: false,
        strict_ssh_host_key: false,
        ssh_cert_path: None,
    })
    .await
    .unwrap();
    assert!(!rep_tls12.tls12_rejected);
    assert_eq!(rep_tls12.verdict, HostProbeVerdict::InsecureConfiguration);
    h2.abort();

    // Open Web UI port 47990 must trigger InsecureConfiguration even on PQ TLS 1.3
    let (pq_port, _, h3) = spawn_mock_tls_server(MockTlsMode::PqOnlyAcceptAnyCert).await;
    let open_webui = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let webui_port = open_webui.local_addr().unwrap().port();
    let rep_webui = probe_host(&HostProbeRequest {
        host: "127.0.0.1".into(),
        https_port: pq_port,
        http_port: alloc_closed_port(),
        webui_port,
        rtsp_port: alloc_closed_port(),
        ssh_target: None,
        require_pq_ssh: false,
        strict_ssh_host_key: false,
        ssh_cert_path: None,
    })
    .await
    .unwrap();
    assert!(rep_webui.port_47990_webui_open);
    assert_eq!(rep_webui.verdict, HostProbeVerdict::InsecureConfiguration);
    drop(open_webui);

    // Open 47989 with closed 47990 yields ReadyNeedsPairingLockdown
    let open_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = open_http.local_addr().unwrap().port();
    let rep_pair = probe_host(&HostProbeRequest {
        host: "127.0.0.1".into(),
        https_port: pq_port,
        http_port,
        webui_port: alloc_closed_port(),
        rtsp_port: alloc_closed_port(),
        ssh_target: None,
        require_pq_ssh: false,
        strict_ssh_host_key: false,
        ssh_cert_path: None,
    })
    .await
    .unwrap();
    assert!(rep_pair.port_47989_http_open);
    assert_eq!(
        rep_pair.verdict,
        HostProbeVerdict::ReadyNeedsPairingLockdown
    );
    h3.abort();
}

#[test]
fn archive_security_rejects_traversal_case_collision_symlinks_and_zip_bombs() {
    let dir = tempdir().unwrap();

    // 1. Valid ZIP & SHA-256 verification
    let valid_zip = dir.path().join("valid.zip");
    {
        let f = std::fs::File::create(&valid_zip).unwrap();
        let mut zw = ZipWriter::new(f);
        zw.start_file("bin/hello.txt", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"secure-desktop-stream").unwrap();
        zw.finish().unwrap();
    }
    let digest = compute_file_sha256(&valid_zip).unwrap();
    verify_archive_file(&valid_zip, &digest, 1024 * 1024).unwrap();
    let out1 = dir.path().join("out1");
    let extracted = extract_zip_safe(&valid_zip, &out1, ExtractionLimits::default()).unwrap();
    assert_eq!(extracted.len(), 1);
    assert!(verify_archive_file(&valid_zip, &"0".repeat(64), 1024 * 1024).is_err());

    // 2. Traversal
    let trav_zip = dir.path().join("trav.zip");
    {
        let f = std::fs::File::create(&trav_zip).unwrap();
        let mut zw = ZipWriter::new(f);
        zw.start_file("../escape.txt", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"bad").unwrap();
        zw.finish().unwrap();
    }
    assert!(extract_zip_safe(
        &trav_zip,
        &dir.path().join("o2"),
        ExtractionLimits::default()
    )
    .is_err());

    // 3. Case collision
    let case_zip = dir.path().join("case.zip");
    {
        let f = std::fs::File::create(&case_zip).unwrap();
        let mut zw = ZipWriter::new(f);
        zw.start_file("App/File.txt", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"a").unwrap();
        zw.start_file("app/file.txt", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(b"b").unwrap();
        zw.finish().unwrap();
    }
    assert!(extract_zip_safe(
        &case_zip,
        &dir.path().join("o3"),
        ExtractionLimits::default()
    )
    .is_err());

    // 4. Symlink member rejected when disallowed
    let sym_zip = dir.path().join("sym.zip");
    {
        let f = std::fs::File::create(&sym_zip).unwrap();
        let mut zw = ZipWriter::new(f);
        zw.add_symlink("evil_link", "/etc/passwd", SimpleFileOptions::default())
            .unwrap();
        zw.finish().unwrap();
    }
    assert!(extract_zip_safe(
        &sym_zip,
        &dir.path().join("o4"),
        ExtractionLimits::default()
    )
    .is_err());

    // 5. Zip bomb uncompressed limit
    let bomb_zip = dir.path().join("bomb.zip");
    {
        let f = std::fs::File::create(&bomb_zip).unwrap();
        let mut zw = ZipWriter::new(f);
        zw.start_file("big.bin", SimpleFileOptions::default())
            .unwrap();
        zw.write_all(&[b'A'; 4096]).unwrap();
        zw.finish().unwrap();
    }
    let tight = ExtractionLimits {
        max_total_bytes: 512,
        max_single_file_bytes: 512,
        ..ExtractionLimits::default()
    };
    assert!(extract_zip_safe(&bomb_zip, &dir.path().join("o5"), tight).is_err());

    // 6. tar.gz extraction & traversal guard
    let tgz = dir.path().join("ok.tar.gz");
    {
        let f = std::fs::File::create(&tgz).unwrap();
        let enc = GzEncoder::new(f, Compression::default());
        let mut tb = tar::Builder::new(enc);
        let data = b"hello-tar";
        let mut hdr = tar::Header::new_gnu();
        hdr.set_size(data.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_cksum();
        tb.append_data(&mut hdr, Path::new("dir/file.txt"), &data[..])
            .unwrap();
        tb.finish().unwrap();
    }
    let tgz_out = dir.path().join("o6");
    let t_files = extract_tar_gz_safe(&tgz, &tgz_out, ExtractionLimits::default()).unwrap();
    assert_eq!(t_files.len(), 1);

    // 7. Magic-byte archive detection regardless of file extension (.archive)
    let zip_alias = dir.path().join("client-release.archive");
    std::fs::copy(&valid_zip, &zip_alias).unwrap();
    assert_eq!(detect_archive_kind(&zip_alias).unwrap(), ArchiveKind::Zip);

    let tgz_alias = dir.path().join("host-release.archive");
    std::fs::copy(&tgz, &tgz_alias).unwrap();
    assert_eq!(detect_archive_kind(&tgz_alias).unwrap(), ArchiveKind::TarGz);
}

#[test]
fn binary_headers_and_manifests_validate_strictly() {
    let mut elf = [0u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[18..20].copy_from_slice(&0x003eu16.to_le_bytes());
    let elf_info = parse_binary_header_bytes(&elf).unwrap();
    assert_eq!(elf_info.format, BinaryFormat::Elf);
    assert_eq!(elf_info.arch, "x86_64");

    let mut pe = [0u8; 128];
    pe[0..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&64u32.to_le_bytes());
    pe[64..68].copy_from_slice(b"PE\0\0");
    pe[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
    let pe_info = parse_binary_header_bytes(&pe).unwrap();
    assert_eq!(pe_info.format, BinaryFormat::Pe);
    assert_eq!(pe_info.arch, "x86_64");

    let mut macho = [0u8; 32];
    macho[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    macho[4..8].copy_from_slice(&0x0100_000cu32.to_le_bytes());
    let macho_info = parse_binary_header_bytes(&macho).unwrap();
    assert_eq!(macho_info.format, BinaryFormat::MachO);
    assert_eq!(macho_info.arch, "arm64");

    assert!(parse_binary_header_bytes(b"not-a-binary").is_err());

    let txt = format!(
        "format=1\nversion=0.1.0\nrevision={}\nfile=sds-installer-0.1.0-linux-x86_64.zip\nsha256={}\nbytes=1024\n",
        "a".repeat(40),
        "b".repeat(64)
    );
    assert!(parse_linux_text_manifest(txt.as_bytes()).is_ok());

    let json = format!(
        r#"{{"format":1,"version":"0.1.0","revision":"{}","builds":{{"arm64":{{"file":"sds-installer-0.1.0-macos-arm64.zip","sha256":"{}","bytes":1024}}}}}}"#,
        "c".repeat(40),
        "d".repeat(64)
    );
    assert!(parse_release_manifest_json(json.as_bytes()).is_ok());
}

#[test]
fn config_generator_enforces_hardening_and_systemd_privileges_split() {
    for profile in [
        HostProfileKind::LinuxVirtualX11,
        HostProfileKind::LinuxPhysicalX11,
        HostProfileKind::WindowsHost,
    ] {
        let bundle = generate_host_bundle(&HostConfigParams {
            instance_name: "sds-host".into(),
            controller_ip: "192.168.10.20".into(),
            profile,
            display: ":97".into(),
            resolution: "1920x1080".into(),
            encoder: EncoderKind::Auto,
            render_device: None,
            enable_clipboard: true,
            enable_file_transfer: true,
            enable_native_file_clipboard: true,
            enable_mic: true,
            firewall_backend: FirewallBackend::Auto,
            install_dir: None,
        })
        .unwrap();

        let conf = &bundle.files["sunshine.conf"].content;
        assert!(conf.contains("origin_web_ui_allowed = pc"));
        assert!(conf.contains("lan_encryption_mode = 2"));
        assert!(conf.contains("wan_encryption_mode = 2"));
        assert!(conf.contains("upnp = disabled"));
        assert!(conf.contains("mdns_advertise = disabled"));
        assert!(conf.contains("sds_default_permissions ="));

        if profile == HostProfileKind::LinuxVirtualX11 {
            let disp_unit = &bundle.files["systemd/sds-host-display.service"].content;
            assert!(
                !disp_unit.contains("NoNewPrivileges"),
                "sds-display.service must NOT set NoNewPrivileges so sudo works in virtual desktop"
            );
            let sun_unit = &bundle.files["systemd/sds-host-sunshine.service"].content;
            assert!(sun_unit.contains("NoNewPrivileges=true"));
            let audio_unit = &bundle.files["systemd/sds-host-audio.service"].content;
            assert!(audio_unit.contains("NoNewPrivileges=true"));

            assert!(bundle
                .files
                .contains_key("systemd/drop-ins/20-private-audio-display.conf"));
            assert_eq!(
                bundle.files["systemd/drop-ins/20-private-audio-display.conf"].target_hint,
                "~/.config/systemd/user/sds-host-display.service.d/20-private-audio.conf"
            );
            assert!(bundle.files.contains_key("lxqt/user-dirs.dirs"));
            let panel = &bundle.files["lxqt/panel.conf"].content;
            assert!(panel.contains("[fancymenu]"));
            assert!(panel.contains("[worldclock]"));
            let start_disp = &bundle.files["start-display.sh"].content;
            assert!(start_disp.contains("mapped_window"));
            assert!(start_disp.contains("tr -d '[:space:]'"));
        }
        if profile == HostProfileKind::LinuxPhysicalX11 {
            let sess = &bundle.files["sds-host-session.sh"].content;
            assert!(sess.contains("if [[ -n \"$output\" ]]; then"));
        }
    }

    let v4: IpAddr = "192.168.10.20".parse().unwrap();
    let fw_ufw = generate_firewall_commands(FirewallBackend::Ufw, v4, true);
    assert!(fw_ufw
        .remove_firewall
        .iter()
        .any(|c| c.contains(r"match(\$0") && c.contains(r"substr(\$0")));
    let fw_fwd = generate_firewall_commands(FirewallBackend::Firewalld, v4, true);
    assert!(fw_fwd
        .remove_firewall
        .iter()
        .any(|c| c.contains("--list-rich-rules") && c.contains("--remove-rich-rule")));

    // Firewall scoping checks across all backends (including IPv6)
    let v6: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    let fw_nft = generate_firewall_commands(FirewallBackend::Nftables, v6, true);
    assert!(fw_nft
        .setup_streaming
        .iter()
        .any(|c| c.contains("ip6 saddr fd00::1")));
    assert!(fw_nft
        .setup_streaming
        .iter()
        .any(|c| c.contains("tcp dport 47990 drop")));
    assert!(fw_nft
        .open_pairing_47989
        .iter()
        .any(|c| c.contains("47989")));
    assert!(fw_nft
        .close_pairing_47989
        .iter()
        .any(|c| c.contains("sds-pairing")));

    // Invalid parameters must be rejected
    assert!(generate_host_bundle(&HostConfigParams {
        instance_name: "bad;name".into(),
        controller_ip: "192.168.10.20".into(),
        profile: HostProfileKind::LinuxVirtualX11,
        display: ":97".into(),
        resolution: "1920x1080".into(),
        encoder: EncoderKind::Auto,
        render_device: None,
        enable_clipboard: true,
        enable_file_transfer: true,
        enable_native_file_clipboard: true,
        enable_mic: true,
        firewall_backend: FirewallBackend::Ufw,
        install_dir: None,
    })
    .is_err());
}

#[test]
fn ui_state_defaults_clean_and_consistent() {
    let pair = ProbePairFormState::default();
    assert_eq!(pair.client_name, "Desktop Controller");
    assert_eq!(pair.admin_user, "sds-admin");
    assert!(pair.require_pq_ssh);

    let client = ClientFormState::default();
    assert!(client.auto_deps);
    assert!(!client.allow_unnotarized);

    let host = HostFormState::default();
    assert!(host.auto_deps);
    assert!(!host.show_advanced);
    assert_eq!(host.instance_name, "sds-host");

    let tabs = UiTab::all();
    assert_eq!(tabs.len(), 5);
    assert_eq!(tabs[4], UiTab::Uninstall);

    let mut secrets = ProbePairFormState {
        admin_pass: "super-secret".into(),
        pin: "4321".into(),
        ..Default::default()
    };
    secrets.clear_secrets();
    assert!(secrets.admin_pass.is_empty());
    assert!(secrets.pin.is_empty());
}

#[tokio::test]
async fn deps_checker_local_report() {
    let rep = check_dependencies(&DependencyCheckRequest {
        role: DependencyRole::Client,
        ssh_target: None,
        require_pq_ssh: true,
        strict_ssh_host_key: false,
    })
    .await
    .expect("check_dependencies failed");

    assert!(!rep.os.is_empty());
    assert!(!rep.arch.is_empty());
    assert_eq!(rep.role, DependencyRole::Client);
    assert!(!rep.items.is_empty());
}

#[test]
fn uninstall_safety_allowlist_and_manifest_roundtrip() {
    let tmp = tempdir().unwrap();
    let home = tmp.path();

    // 1. Root / home / top-level protection
    assert!(!is_safe_sds_removal_path(Path::new("/"), home, true));
    assert!(!is_safe_sds_removal_path(Path::new("/etc"), home, true));
    assert!(!is_safe_sds_removal_path(
        Path::new("/Applications"),
        home,
        true
    ));
    assert!(!is_safe_sds_removal_path(home, home, true));
    assert!(!is_safe_sds_removal_path(&home.join(".config"), home, true));
    assert!(!is_safe_sds_removal_path(&home.join(".local"), home, true));

    // 2. Traversal rejection
    assert!(!is_safe_sds_removal_path(&home.join("../evil"), home, true));
    assert!(!is_safe_sds_removal_path(
        &home.join(".local/share/../evil"),
        home,
        true
    ));

    // 3. Unrelated application path rejection
    assert!(!is_safe_sds_removal_path(
        &home.join(".config/google-chrome"),
        home,
        true
    ));
    assert!(!is_safe_sds_removal_path(
        &home.join(".config/systemd/user/other.service"),
        home,
        true
    ));

    // 4. Exact safe non-config paths
    assert!(is_safe_sds_removal_path(
        &home.join(".local/share/sds-client"),
        home,
        false
    ));
    assert!(is_safe_sds_removal_path(
        &home.join(".local/bin/moonlight-sds"),
        home,
        false
    ));
    assert!(is_safe_sds_removal_path(
        &home.join(".local/share/applications/sds-moonlight.desktop"),
        home,
        false
    ));
    assert!(is_safe_sds_removal_path(
        &home.join(".local/share/sds-installer"),
        home,
        false
    ));

    // 5. Valid slug paths
    assert!(is_safe_sds_removal_path(
        Path::new("/opt/secure-desktop-stream-sds-host"),
        home,
        false
    ));
    assert!(is_safe_sds_removal_path(
        &home.join(".local/share/sds-installer-stage/sds-host"),
        home,
        false
    ));
    assert!(is_safe_sds_removal_path(
        &home.join(".config/systemd/user/sds-host-sunshine.service"),
        home,
        false
    ));
    assert!(is_safe_sds_removal_path(
        &home.join(".config/systemd/user/sds-host-display.service.d"),
        home,
        false
    ));
    assert!(!is_safe_sds_removal_path(
        &home.join(".config/systemd/user/./sds-host-sunshine.service"),
        home,
        true
    ));

    // 6. Purge-only config paths
    let sunshine_cfg = home.join(".config/sds-host-sunshine");
    assert!(!is_safe_sds_removal_path(&sunshine_cfg, home, false));
    assert!(is_safe_sds_removal_path(&sunshine_cfg, home, true));

    // 7. Manifest persistence roundtrip
    let client_path = home.join(".local/share/sds-client/app");
    let client_cfg = home.join(".local/share/sds-client/client-receipt.json");
    record_client_install(
        home,
        "linux",
        std::slice::from_ref(&client_path),
        std::slice::from_ref(&client_cfg),
    )
    .unwrap();

    let manifest = load_manifest(home, "linux");
    assert!(manifest
        .client_paths
        .iter()
        .any(|p| p.contains("sds-client")));
    assert!(manifest
        .client_config_paths
        .iter()
        .any(|p| p.contains("client-receipt")));

    let host_entry = HostManifestEntry {
        instance_name: "sds-host".into(),
        install_dir: "/opt/secure-desktop-stream-sds-host".into(),
        systemd_units: vec!["sds-host-sunshine.service".into()],
        firewall_backend: Some(FirewallBackend::Ufw),
        paths: vec!["/opt/secure-desktop-stream-sds-host".into()],
        config_paths: vec![sunshine_cfg.display().to_string()],
    };
    record_host_install(home, "linux", host_entry).unwrap();

    let manifest2 = load_manifest(home, "linux");
    assert_eq!(manifest2.host_instances.len(), 1);
    assert_eq!(manifest2.host_instances[0].instance_name, "sds-host");
}

#[test]
fn select_ui_launch_mode_respects_platform_display_ssh_and_tty() {
    assert_eq!(
        select_ui_launch_mode(false, false, "macos", true, false, true),
        UiLaunchMode::NativeGui
    );
    assert_eq!(
        select_ui_launch_mode(false, false, "linux", true, false, true),
        UiLaunchMode::NativeGui
    );
    assert_eq!(
        select_ui_launch_mode(false, false, "linux", false, true, true),
        UiLaunchMode::Tui
    );
    assert_eq!(
        select_ui_launch_mode(false, false, "linux", true, true, true),
        UiLaunchMode::Tui
    );
    assert_eq!(
        select_ui_launch_mode(false, false, "linux", false, false, true),
        UiLaunchMode::Tui
    );
    assert_eq!(
        select_ui_launch_mode(false, false, "linux", false, false, false),
        UiLaunchMode::NonInteractiveCli
    );
    assert_eq!(
        select_ui_launch_mode(true, false, "linux", false, true, false),
        UiLaunchMode::NativeGui
    );
    assert_eq!(
        select_ui_launch_mode(false, true, "macos", true, false, true),
        UiLaunchMode::Tui
    );
}

#[test]
fn ui_state_validates_forms_and_clears_secrets() {
    let mut client = ClientFormState {
        source_kind: ClientSourceKind::ReleaseUrl,
        archive_location: "http://insecure.example.com/app.zip".into(),
        sha256: "a".repeat(64),
        ..Default::default()
    };
    assert!(client.to_client_install_request(true).is_err());

    client.archive_location = "https://releases.example.com/app.zip#frag".into();
    assert!(client.to_client_install_request(true).is_err());

    client.archive_location = "https://releases.example.com:8443/app.zip".into();
    assert!(client.to_client_install_request(true).is_ok());

    assert!(validate_https_url("https://releases.example.com:0/app.zip").is_err());

    let mut host = HostFormState {
        ssh_target: "user@linux-host".into(),
        host_ip: "192.0.2.50".into(),
        controller_ip: "bad-ip".into(),
        ..Default::default()
    };
    assert!(host.to_ssh_deploy_request(true).is_err());

    host.controller_ip = "192.0.2.10".into();
    host.archive_path = "/tmp/sunshine.tar.gz".into();
    host.archive_sha256 = "not-hex".into();
    assert!(host.to_ssh_deploy_request(true).is_err());

    host.archive_sha256 = "f".repeat(64);
    let ssh_req = host.to_ssh_deploy_request(true).unwrap();
    assert_eq!(
        ssh_req.archive_sha256.as_deref(),
        Some("f".repeat(64).as_str())
    );

    let mut pair = ProbePairFormState {
        host: "192.0.2.50".into(),
        ssh_target: "user@linux-host".into(),
        controller_ip: "192.0.2.10".into(),
        pin: "1234".into(),
        admin_user: "sds-admin".into(),
        admin_pass: "secret-passphrase".into(),
        ..Default::default()
    };
    let pin_req = pair.to_submit_pin_request("sess-1").unwrap();
    assert_eq!(pin_req.permissions.len(), 5);
    pair.clear_secrets();
    assert!(pair.admin_pass.is_empty());
    assert!(pair.pin.is_empty());
}

#[test]
fn native_tui_renders_all_tabs_masks_passwords_and_shows_confirm() {
    let backend = TestBackend::new(110, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    let mut app = TuiApp::new(None);
    app.probe_pair.admin_pass = "hunter2secret".into();

    for tab in UiTab::all() {
        app.tab = tab;
        terminal.draw(|f| render_tui_frame(f, &app)).unwrap();
        let buf = terminal.backend().buffer();
        let rendered: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(!rendered.contains("hunter2secret"));
        assert!(!rendered.is_empty());
    }

    app.pending_confirm = Some(PendingConfirmation::UninstallPurge);
    terminal.draw(|f| render_tui_frame(f, &app)).unwrap();
    let buf = terminal.backend().buffer();
    let rendered: String = buf.content().iter().map(|c| c.symbol()).collect();
    assert!(rendered.contains("Confirmation"));
}

#[test]
fn http_chunked_decoder_handles_frames_and_rejects_malformed() {
    let payload = b"5\r\nhello\r\n7;ext=1\r\n world!\r\n0\r\n\r\n";
    let decoded = decode_chunked_bytes(payload).unwrap();
    assert_eq!(decoded, b"hello world!");
    assert!(decode_chunked_bytes(b"zzz\r\nbad\r\n0\r\n\r\n").is_err());
    assert!(decode_chunked_bytes(b"10\r\nshort\r\n").is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn uninstall_refuses_to_traverse_symlinked_ancestors() {
    let tmp = tempdir().unwrap();
    let fake_home = tmp.path().join("home");
    let outside = tmp.path().join("outside");
    let marker = outside.join("sds-host-sunshine/important.txt");
    std::fs::create_dir_all(marker.parent().unwrap()).unwrap();
    std::fs::write(&marker, b"keep-me").unwrap();

    std::fs::create_dir_all(&fake_home).unwrap();
    std::os::unix::fs::symlink(&outside, fake_home.join(".config")).unwrap();

    let res = run_uninstall_for_home(
        &UninstallRequest {
            component: UninstallComponent::Host,
            instance_name: "sds-host".into(),
            purge_config: true,
            remove_firewall: false,
            ssh_target: None,
            require_pq_ssh: false,
            strict_ssh_host_key: false,
            execute_sudo: false,
            user_only: true,
            dry_run: false,
        },
        &fake_home,
        "linux",
        &ProgressEmitter::new(None),
    )
    .await
    .unwrap();

    assert!(
        marker.exists(),
        "outside target must not be deleted through symlink"
    );
    assert!(
        res.skipped_or_protected_paths
            .iter()
            .any(|p| p.contains("sds-host-sunshine")),
        "expected symlink-backed target to be skipped"
    );
}
