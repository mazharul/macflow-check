use macflow_scan::{
    inspect_env_content, inspect_ssh_key_content, render_json, render_report, Inspection,
    ScanResult, SSH_SUB_CATEGORY,
};

#[path = "support/fake_keys.rs"]
mod fake_keys;

#[test]
fn test_privacy_plaintext_keys_never_leaked_in_findings_json_or_report() {
    let s_ant = format!("9f8e{}", "7d6c".repeat(7));
    let s_oai = format!("1a2b{}", "3c4d".repeat(8));
    let s_hf = format!("ZzYy{}", "XxWw".repeat(7));
    let (ant, oai, hf) = (
        format!("sk-ant-api03-{s_ant}"),
        ["sk-proj-", &s_oai].concat(),
        format!("hf_{s_hf}"),
    );

    let env_fixture =
        format!("export ANTHROPIC_API_KEY=\"{ant}\"\nOPENAI_API_KEY={oai}\nset -x HF_TOKEN {hf}\n");
    let (findings, insp) = inspect_env_content(&env_fixture, "/Users/dev/.zshrc", "user");
    assert_eq!(findings.len(), 3);

    let result = ScanResult::new(findings.clone(), vec![insp], "2026-10-21T00:00:00Z");
    let (json_out, full_json, report_out) = (
        serde_json::to_string(&findings).unwrap(),
        render_json(&result).unwrap(),
        render_report(&result),
    );

    for secret in [&ant, &oai, &hf, &s_ant, &s_oai, &s_hf] {
        assert!(!json_out.contains(secret.as_str()));
        assert!(!full_json.contains(secret.as_str()));
        assert!(!report_out.contains(secret.as_str()));
        for f in &findings {
            assert!(!f.title.contains(secret.as_str()));
            assert!(!f.description.contains(secret.as_str()));
            assert!(!f
                .remediation
                .as_deref()
                .unwrap_or("")
                .contains(secret.as_str()));
        }
    }

    for expected in [
        "sk-ant-...",
        "sk-proj-...",
        "hf_...",
        "/Users/dev/.zshrc:1",
        "/Users/dev/.zshrc:2",
        "/Users/dev/.zshrc:3",
    ] {
        assert!(report_out.contains(expected), "Missing {expected}");
    }
}

#[test]
fn test_privacy_ssh_keys_never_leaked_in_findings_json_or_report() {
    let unencrypted_openssh_key = fake_keys::openssh("none", "none");
    let findings = inspect_ssh_key_content(
        &unencrypted_openssh_key,
        "/Users/dev/.ssh/id_ed25519",
        false,
    );
    assert_eq!(findings.len(), 1);

    let insp = Inspection::inspected(
        macflow_scan::Category::Security,
        Some(SSH_SUB_CATEGORY),
        "user",
    );
    let result = ScanResult::new(findings.clone(), vec![insp], "2026-10-21T00:00:00Z");
    let (json_out, full_json, report_out) = (
        serde_json::to_string(&findings).unwrap(),
        render_json(&result).unwrap(),
        render_report(&result),
    );

    // No line of the key body, nor its decoded magic, may reach the output.
    let mut fragments: Vec<&str> = unencrypted_openssh_key
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    fragments.extend(["b3BlbnNzaC1rZXktdjE", "openssh-key-v1"]);

    for fragment in fragments {
        assert!(!json_out.contains(fragment));
        assert!(!full_json.contains(fragment));
        assert!(!report_out.contains(fragment));
        for f in &findings {
            assert!(!f.title.contains(fragment));
            assert!(!f.description.contains(fragment));
            assert!(!f.remediation.as_deref().unwrap_or("").contains(fragment));
        }
    }

    assert!(report_out.contains("/Users/dev/.ssh/id_ed25519:1"));
    assert!(report_out.contains("Unencrypted SSH private key"));
}

#[test]
fn test_privacy_shell_history_secrets_never_leaked_in_report_or_json() {
    let home = std::env::temp_dir().join(format!(
        "macflow_hist_privacy_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let ant = format!("sk-ant-api03-{}", "Q".repeat(40));
    let bearer = "Z".repeat(32);
    std::fs::write(
        home.join(".zsh_history"),
        format!(": 1:0;export ANTHROPIC_API_KEY={ant}\n: 2:0;curl -H 'Authorization: Bearer {bearer}' https://api.x\n: 3:0;psql postgres://admin:s3cretpass@db/app\n"),
    )
    .unwrap();
    let (findings, inspections) =
        macflow_scan::scan_shell_with_home(&macflow_scan::ScanContext::new(), Some(&home));
    assert_eq!(findings.len(), 1);
    let result = ScanResult::new(findings, inspections, "2026-10-26T00:00:00Z");
    let (json, report) = (render_json(&result).unwrap(), render_report(&result));
    for fragment in [
        &ant[7..],
        bearer.as_str(),
        "s3cretpass",
        "ANTHROPIC_API_KEY=",
        "Authorization",
    ] {
        assert!(!json.contains(fragment), "json leaked {fragment}");
        assert!(!report.contains(fragment), "report leaked {fragment}");
    }
    assert!(report.contains("sk-ant-...") && report.contains("password in URL"));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn test_privacy_plaintext_credential_values_never_leaked() {
    let pw = concat!("pass", "word");
    let home = std::env::temp_dir().join(format!(
        "macflow_cred_privacy_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let v = "QQQQQQQQQQQQQQQQQQQQQQQQ";
    let files = [
        (
            ".npmrc",
            format!("//registry.npmjs.org/:_authToken=npm_{v}"),
        ),
        (".yarnrc.yml", format!("npmAuthToken: npm_{v}")),
        (".pypirc", format!("[pypi]\n{pw} = pypi-{v}")),
        (
            ".gem/credentials",
            format!(":rubygems_api_key: rubygems_{v}"),
        ),
        (
            ".cargo/credentials.toml",
            format!("[registry]\ntoken = \"cio{v}\""),
        ),
        (".git-credentials", format!("https://me:ghp_{v}@github.com")),
        (".netrc", format!("machine x.example login me {pw} {v}")),
        (
            ".config/pip/pip.conf",
            format!("[global]\nindex-url = https://me:{v}@pypi.example/simple"),
        ),
        (
            ".config/gh/hosts.yml",
            format!("github.com:\n    oauth_token: gho_{v}"),
        ),
        (
            ".docker/config.json",
            format!("{{\"auths\": {{\"ghcr.io\": {{\"auth\": \"{v}\"}}}}}}"),
        ),
        (
            ".aws/credentials",
            format!("[default]\naws_access_key_id = AKIA{v}"),
        ),
        (
            ".kube/config",
            format!("clusters:\n- cluster:\n    server: https://k.example\n  name: k\ncontexts:\n- context:\n    cluster: k\n    user: u\n  name: k\nusers:\n- name: u\n  user:\n    token: {v}\n"),
        ),
    ];
    for (rel, body) in &files {
        let p = home.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }
    let (findings, inspections) =
        macflow_scan::scan_credentials_with_home(&macflow_scan::ScanContext::new(), Some(&home));
    assert_eq!(findings.len(), files.len());
    let result = ScanResult::new(findings, inspections, "2026-10-26T00:00:00Z");
    let (json, report) = (render_json(&result).unwrap(), render_report(&result));
    assert!(
        !json.contains(v) && !report.contains(v),
        "credential value leaked"
    );
    let _ = std::fs::remove_dir_all(&home);
}
