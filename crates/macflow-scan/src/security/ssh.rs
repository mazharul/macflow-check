use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const SSH_SUB_CATEGORY: &str = "SSH keys and config";

fn make_finding(
    id: &str,
    title: &str,
    sev: Severity,
    desc: impl Into<String>,
    rem: impl Into<String>,
    path: &str,
    line: usize,
) -> Finding {
    Finding::new(id, title, Category::Security, sev, desc)
        .with_sub_category(SSH_SUB_CATEGORY)
        .with_scope("user")
        .with_location(path, Some(line))
        .with_remediation(rem)
}

/// Decodes standard RFC 4648 base64 without external dependencies.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let (mut buf, mut bits) = (0u32, 0);
    for &b in input.as_bytes() {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' | b' ' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Checks if an OpenSSH private key binary payload is unencrypted.
///
/// Per OpenSSH PROTOCOL.key:
/// - starts with b"openssh-key-v1\0" (15 bytes)
/// - ciphername string (u32 be length + bytes)
/// - kdfname string (u32 be length + bytes)
///
/// Unencrypted if and only if both ciphername == "none" and kdfname == "none".
fn is_openssh_key_unencrypted(bytes: &[u8]) -> bool {
    const MAGIC: &[u8] = b"openssh-key-v1\0";
    if bytes.len() < 19 || &bytes[..15] != MAGIC {
        return false;
    }
    let c_len = u32::from_be_bytes([bytes[15], bytes[16], bytes[17], bytes[18]]) as usize;
    let c_end = 19 + c_len;
    if bytes.len() < c_end + 4 {
        return false;
    }
    let k_len = u32::from_be_bytes([
        bytes[c_end],
        bytes[c_end + 1],
        bytes[c_end + 2],
        bytes[c_end + 3],
    ]) as usize;
    let k_end = c_end + 4 + k_len;
    if bytes.len() < k_end {
        return false;
    }
    &bytes[19..c_end] == b"none" && &bytes[c_end + 4..k_end] == b"none"
}

/// Parses an SSH config line into key and value, supporting whitespace and '=' delimiters.
fn parse_config_entry(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let sep_idx = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = &line[..sep_idx];
    let mut val = line[sep_idx..].trim_start();
    if let Some(stripped) = val.strip_prefix('=') {
        val = stripped.trim_start();
    }
    Some((key, val))
}

/// Extracts identity file names specified in ~/.ssh/config, categorized by wildcard vs specific hosts.
pub fn parse_ssh_config_identity_files(content: &str) -> (HashSet<String>, HashSet<String>) {
    let (mut wildcard_keys, mut specific_keys) = (HashSet::new(), HashSet::new());
    let mut current_is_wildcard = true;

    for line in content.lines() {
        let Some((key, val)) = parse_config_entry(line) else {
            continue;
        };
        if key.eq_ignore_ascii_case("host") {
            current_is_wildcard = val.split_whitespace().any(|p| p == "*");
        } else if key.eq_ignore_ascii_case("match") {
            current_is_wildcard = false;
        } else if key.eq_ignore_ascii_case("identityfile") {
            let clean_val = val.trim_matches(|c| c == '"' || c == '\'');
            let key_name = Path::new(clean_val)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| clean_val.to_string());
            let target = if current_is_wildcard {
                &mut wildcard_keys
            } else {
                &mut specific_keys
            };
            target.insert(clean_val.to_string());
            target.insert(key_name);
        }
    }
    (wildcard_keys, specific_keys)
}

/// Inspects content of an SSH private key file. Never reveals key bytes or payload.
pub fn inspect_ssh_key_content(
    content: &str,
    file_path: &str,
    is_scoped_to_specific_host: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("-----BEGIN ") {
            continue;
        }
        let line_num = idx + 1;
        let sev = if is_scoped_to_specific_host {
            Severity::Info
        } else {
            Severity::Medium
        };
        let rem = format!(
            "Run `ssh-keygen -p -f {}` to add a passphrase, and use macOS Keychain (UseKeychain yes + AddKeysToAgent yes).",
            file_path
        );

        let unenc_format = if trimmed == "-----BEGIN OPENSSH PRIVATE KEY-----" {
            let mut body = String::new();
            for sub in &lines[idx + 1..] {
                let st = sub.trim();
                if st == "-----END OPENSSH PRIVATE KEY-----" {
                    break;
                }
                body.push_str(st);
            }
            decode_base64(&body)
                .and_then(|bytes| is_openssh_key_unencrypted(&bytes).then_some("OpenSSH"))
        } else if trimmed == "-----BEGIN RSA PRIVATE KEY-----"
            || trimmed == "-----BEGIN DSA PRIVATE KEY-----"
            || trimmed == "-----BEGIN EC PRIVATE KEY-----"
            || trimmed == "-----BEGIN OPENSSL PRIVATE KEY-----"
        {
            let is_enc = lines[idx + 1..].iter().any(|sub| {
                let st = sub.trim().to_ascii_uppercase();
                st.starts_with("PROC-TYPE:") && st.contains("ENCRYPTED")
            });
            (!is_enc).then_some("PEM")
        } else if trimmed == "-----BEGIN PRIVATE KEY-----" {
            Some("PKCS#8")
        } else {
            None
        };

        if let Some(fmt) = unenc_format {
            findings.push(make_finding(
                "ssh-unencrypted-private-key",
                "Unencrypted SSH private key",
                sev,
                format!(
                    "Unencrypted {fmt} private key detected on disk without passphrase encryption."
                ),
                rem,
                file_path,
                line_num,
            ));
        }
    }
    findings
}

/// Inspects ~/.ssh/config content for risky SSH configuration directives.
pub fn inspect_ssh_config_content(content: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_host_is_wildcard = false;

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let Some((key, val)) = parse_config_entry(line) else {
            continue;
        };

        if key.eq_ignore_ascii_case("host") {
            current_host_is_wildcard = val.split_whitespace().any(|p| p == "*");
        } else if key.eq_ignore_ascii_case("match") {
            current_host_is_wildcard = false;
        }

        if current_host_is_wildcard
            && key.eq_ignore_ascii_case("forwardagent")
            && val.eq_ignore_ascii_case("yes")
        {
            findings.push(make_finding(
                "ssh-config-forward-agent-wildcard",
                "ForwardAgent enabled for wildcard host",
                Severity::Low,
                "ForwardAgent is enabled under Host *, which can allow remote servers to access the local SSH agent.",
                "Limit ForwardAgent to specific trusted host entries instead of Host *.",
                file_path,
                line_num,
            ));
        }

        if key.eq_ignore_ascii_case("stricthostkeychecking")
            && (val.eq_ignore_ascii_case("no") || val.eq_ignore_ascii_case("off"))
        {
            findings.push(make_finding(
                "ssh-config-strict-host-checking-disabled",
                "StrictHostKeyChecking disabled",
                Severity::Low,
                "StrictHostKeyChecking is disabled, allowing connections to unverified or changed host keys without warning.",
                "Set StrictHostKeyChecking to 'yes' or 'accept-new' to verify remote host keys.",
                file_path,
                line_num,
            ));
        }

        if key.eq_ignore_ascii_case("userknownhostsfile")
            && (val == "/dev/null"
                || val.starts_with("/dev/null ")
                || val.starts_with("\"/dev/null\""))
        {
            findings.push(make_finding(
                "ssh-config-user-known-hosts-dev-null",
                "UserKnownHostsFile discarded to /dev/null",
                Severity::Low,
                "UserKnownHostsFile is set to /dev/null, disabling persistence and verification of known host keys.",
                "Remove UserKnownHostsFile /dev/null so host keys are verified and stored.",
                file_path,
                line_num,
            ));
        }

        if (key.eq_ignore_ascii_case("proxycommand") || key.eq_ignore_ascii_case("localcommand"))
            && (val.contains("/tmp") || val.contains("/private/tmp"))
        {
            findings.push(make_finding(
                "ssh-config-command-tmp-path",
                "SSH command references temporary directory",
                Severity::Low,
                format!("{key} executes an executable or script from a temporary directory (/tmp or /private/tmp)."),
                "Move scripts and commands out of temporary directories into a permanent binary directory.",
                file_path,
                line_num,
            ));
        }
    }
    findings
}

/// Inspects ~/.ssh/authorized_keys content for forced command directives.
pub fn inspect_authorized_keys_content(content: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.contains("command=") || trimmed.contains("command =") {
            findings.push(make_finding(
                "ssh-authorized-keys-command",
                "Forced command directive in authorized_keys",
                Severity::Low,
                "Authorized keys line contains a forced command= execution directive.",
                "Verify that the forced command directive in authorized_keys is intentional and expected.",
                file_path,
                idx + 1,
            ));
        }
    }
    findings
}

/// Scans the user's ~/.ssh directory using the default home directory.
pub fn scan_ssh(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    scan_ssh_with_home(ctx, None)
}

/// Scans the user's ~/.ssh directory with an optional home directory override.
pub fn scan_ssh_with_home(
    ctx: &ScanContext,
    home_override: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let mut findings = Vec::new();
    let mut inspections = Vec::new();

    if !ctx.is_category_selected(Category::Security) {
        inspections.push(Inspection::skipped(
            Category::Security,
            Some(SSH_SUB_CATEGORY),
            Some("category not selected"),
        ));
        return (findings, inspections);
    }

    let home_dir = home_override
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("MACFLOW_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from));

    let Some(home) = home_dir else {
        inspections.push(Inspection::skipped(
            Category::Security,
            Some(SSH_SUB_CATEGORY),
            Some("home directory unavailable"),
        ));
        return (findings, inspections);
    };

    let ssh_dir = home.join(".ssh");
    if !ssh_dir.is_dir() {
        inspections.push(Inspection::inspected(
            Category::Security,
            Some(SSH_SUB_CATEGORY),
            "user (~/.ssh not present)",
        ));
        return (findings, inspections);
    }

    let config_path = ssh_dir.join("config");
    let (wildcard_keys, specific_keys) = match std::fs::read_to_string(&config_path) {
        Ok(c) => {
            findings.extend(inspect_ssh_config_content(
                &c,
                &config_path.to_string_lossy(),
            ));
            parse_ssh_config_identity_files(&c)
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            inspections.push(Inspection::unparseable(
                Category::Security,
                Some(SSH_SUB_CATEGORY),
                Some(&config_path.to_string_lossy()),
                e.to_string(),
            ));
            (HashSet::new(), HashSet::new())
        }
        _ => (HashSet::new(), HashSet::new()),
    };

    let auth_path = ssh_dir.join("authorized_keys");
    match std::fs::read_to_string(&auth_path) {
        Ok(c) => findings.extend(inspect_authorized_keys_content(
            &c,
            &auth_path.to_string_lossy(),
        )),
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            inspections.push(Inspection::unparseable(
                Category::Security,
                Some(SSH_SUB_CATEGORY),
                Some(&auth_path.to_string_lossy()),
                e.to_string(),
            ))
        }
        _ => {}
    }

    if let Ok(entries) = std::fs::read_dir(&ssh_dir) {
        let mut sorted_entries: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|de| de.path()))
            .filter(|p| p.is_file())
            .collect();
        sorted_entries.sort();

        for p in sorted_entries {
            let file_name = p.file_name().unwrap_or_default().to_string_lossy();
            if file_name.ends_with(".pub")
                || file_name == "config"
                || file_name == "authorized_keys"
                || file_name == "authorized_keys2"
                || file_name.starts_with("known_hosts")
            {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&p) {
                if content.contains("-----BEGIN ") && content.contains("PRIVATE KEY-----") {
                    let path_str = p.to_string_lossy();
                    let is_wildcard = wildcard_keys.contains(file_name.as_ref())
                        || wildcard_keys.contains(path_str.as_ref());
                    let is_specific = specific_keys.contains(file_name.as_ref())
                        || specific_keys.contains(path_str.as_ref());
                    let is_scoped = is_specific && !is_wildcard;
                    findings.extend(inspect_ssh_key_content(&content, &path_str, is_scoped));
                }
            }
        }
    }

    inspections.push(Inspection::inspected(
        Category::Security,
        Some(SSH_SUB_CATEGORY),
        "user",
    ));

    (findings, inspections)
}
