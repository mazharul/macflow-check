use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use macflow_scan::{
    inspect_authorized_keys_content, inspect_ssh_config_content, inspect_ssh_key_content,
    scan_ssh_with_home, Category, InspectionStatus, ScanContext, Severity,
};

#[path = "support/fake_keys.rs"]
mod fake_keys;
use fake_keys::{openssh, pem, FILLER};

fn fixture_unencrypted_openssh() -> String {
    openssh("none", "none")
}

fn fixture_encrypted_openssh() -> String {
    openssh("aes256-ctr", "bcrypt")
}

fn fixture_unencrypted_rsa_pem() -> String {
    pem("RSA ", &[], FILLER)
}

fn fixture_encrypted_rsa_pem() -> String {
    pem(
        "RSA ",
        &[
            "Proc-Type: 4,ENCRYPTED",
            "DEK-Info: AES-128-CBC,00000000000000000000000000000000",
        ],
        FILLER,
    )
}

fn fixture_unencrypted_pkcs8() -> String {
    pem("", &[], FILLER)
}

fn fixture_encrypted_pkcs8() -> String {
    pem("ENCRYPTED ", &[], FILLER)
}

#[test]
fn test_unencrypted_openssh_key_detection() {
    let findings = inspect_ssh_key_content(
        &fixture_unencrypted_openssh(),
        "/Users/dev/.ssh/id_ed25519",
        false,
    );
    assert_eq!(findings.len(), 1);
    let f = &findings[0];
    assert_eq!(f.id, "ssh-unencrypted-private-key");
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.category, Category::Security);
    assert!(f.description.contains("OpenSSH"));
    assert!(f
        .remediation
        .as_deref()
        .unwrap()
        .contains("ssh-keygen -p -f"));
}

#[test]
fn test_encrypted_openssh_key_ignored() {
    let f = inspect_ssh_key_content(
        &fixture_encrypted_openssh(),
        "/Users/dev/.ssh/id_ed25519_enc",
        false,
    );
    assert!(
        f.is_empty(),
        "Encrypted OpenSSH key should not trigger a finding"
    );
}

#[test]
fn test_unencrypted_rsa_pem_key_detection() {
    let findings = inspect_ssh_key_content(
        &fixture_unencrypted_rsa_pem(),
        "/Users/dev/.ssh/id_rsa",
        false,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].description.contains("PEM"));
}

#[test]
fn test_encrypted_rsa_pem_key_ignored() {
    let f = inspect_ssh_key_content(
        &fixture_encrypted_rsa_pem(),
        "/Users/dev/.ssh/id_rsa_enc",
        false,
    );
    assert!(
        f.is_empty(),
        "Encrypted RSA PEM key should not trigger a finding"
    );
}

#[test]
fn test_unencrypted_pkcs8_key_detection() {
    let findings =
        inspect_ssh_key_content(&fixture_unencrypted_pkcs8(), "/Users/dev/.ssh/id_p8", false);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::Medium);
    assert!(findings[0].description.contains("PKCS#8"));
}

#[test]
fn test_encrypted_pkcs8_key_ignored() {
    let f = inspect_ssh_key_content(
        &fixture_encrypted_pkcs8(),
        "/Users/dev/.ssh/id_p8_enc",
        false,
    );
    assert!(
        f.is_empty(),
        "Encrypted PKCS#8 key should not trigger a finding"
    );
}

#[test]
fn test_ssh_key_scoped_to_specific_host_has_info_severity() {
    let f_scoped = inspect_ssh_key_content(
        &fixture_unencrypted_openssh(),
        "/Users/dev/.ssh/id_scoped",
        true,
    );
    assert_eq!(f_scoped.len(), 1);
    assert_eq!(f_scoped[0].severity, Severity::Info);

    let f_unscoped = inspect_ssh_key_content(
        &fixture_unencrypted_openssh(),
        "/Users/dev/.ssh/id_unscoped",
        false,
    );
    assert_eq!(f_unscoped.len(), 1);
    assert_eq!(f_unscoped[0].severity, Severity::Medium);
}

#[test]
fn test_risky_ssh_config_detection() {
    let risky_config = "\
Host *
    ForwardAgent yes
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ProxyCommand /tmp/tunnel.sh %h %p
    LocalCommand /private/tmp/post_connect.sh
";
    let findings = inspect_ssh_config_content(risky_config, "/Users/dev/.ssh/config");
    assert_eq!(findings.len(), 5);
    for f in &findings {
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.category, Category::Security);
    }
    let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"ssh-config-forward-agent-wildcard"));
    assert!(ids.contains(&"ssh-config-strict-host-checking-disabled"));
    assert!(ids.contains(&"ssh-config-user-known-hosts-dev-null"));
    assert_eq!(
        ids.iter()
            .filter(|&&id| id == "ssh-config-command-tmp-path")
            .count(),
        2
    );
}

#[test]
fn test_safe_ssh_config_zero_findings() {
    let safe_config = "\
Host prod-bastion.internal
    ForwardAgent yes
    IdentityFile ~/.ssh/prod_bastion_key
Host github.com
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts
    ProxyCommand /usr/local/bin/cloud-proxy %h %p
Host *
    ForwardAgent no
    StrictHostKeyChecking yes
";
    let findings = inspect_ssh_config_content(safe_config, "/Users/dev/.ssh/config");
    assert!(findings.is_empty(), "Safe config should produce 0 findings");
}

#[test]
fn test_authorized_keys_command_directive_detection() {
    let auth_keys = "\
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleValidKey user1@laptop
command=\"/usr/local/bin/backup-only.sh\",no-pty ssh-rsa AAAAB3NzaC1yc2E backup@server
# command=\"ignored comment line\" ssh-rsa AAAAB3NzaC1yc2E
";
    let findings = inspect_authorized_keys_content(auth_keys, "/Users/dev/.ssh/authorized_keys");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "ssh-authorized-keys-command");
    assert_eq!(findings[0].severity, Severity::Low);
    assert_eq!(findings[0].line_number, Some(2));
}

#[test]
fn test_scan_ssh_with_home_end_to_end() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!("macflow_ssh_test_{ts}"));
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).unwrap();

    let config = "Host corp.example.com\n  IdentityFile ~/.ssh/id_corp\nHost *\n  IdentityFile ~/.ssh/id_wildcard\n  StrictHostKeyChecking no\n";
    fs::write(ssh_dir.join("config"), config).unwrap();
    fs::write(
        ssh_dir.join("authorized_keys"),
        "command=\"/bin/sync\" ssh-ed25519 AAAAC3... dev@test\n",
    )
    .unwrap();
    fs::write(ssh_dir.join("id_corp"), fixture_unencrypted_openssh()).unwrap();
    fs::write(ssh_dir.join("id_wildcard"), fixture_unencrypted_rsa_pem()).unwrap();
    fs::write(ssh_dir.join("id_enc"), fixture_encrypted_openssh()).unwrap();
    fs::write(
        ssh_dir.join("id_corp.pub"),
        "ssh-ed25519 AAAAC3... dev@test\n",
    )
    .unwrap();

    let ctx = ScanContext::default();
    let (findings, inspections) = scan_ssh_with_home(&ctx, Some(&home));

    assert_eq!(inspections.len(), 1);
    assert_eq!(
        inspections[0].status,
        InspectionStatus::Inspected {
            inspected_scope: "user".into()
        }
    );
    assert_eq!(findings.len(), 4);

    let corp = findings
        .iter()
        .find(|f| f.file_path.as_deref().unwrap_or("").ends_with("id_corp"))
        .unwrap();
    assert_eq!(corp.severity, Severity::Info);

    let wildcard = findings
        .iter()
        .find(|f| {
            f.file_path
                .as_deref()
                .unwrap_or("")
                .ends_with("id_wildcard")
        })
        .unwrap();
    assert_eq!(wildcard.severity, Severity::Medium);

    let _ = fs::remove_dir_all(&home);
}

/// Secret scanners flag key-shaped literals in source, even fake ones. Test
/// keys must come from `support/fake_keys.rs`, built at runtime.
#[test]
fn test_no_private_key_literals_in_test_sources() {
    let needle = concat!("PRIVATE", " KEY-----");
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dirs = [crate_dir.join("tests"), crate_dir.join("../../tests")];
    let mut offenders = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = dirs.to_vec();
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && fs::read_to_string(&path).is_ok_and(|s| s.contains(needle))
            {
                offenders.push(path.display().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "key-shaped literals in: {offenders:?}"
    );
}
