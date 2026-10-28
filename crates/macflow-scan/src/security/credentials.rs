//! Developer credentials stored in plaintext files: the exact files supply-chain
//! worms and macOS stealers harvest (Shai-Hulud 2.0,
//! https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/ ;
//! s1ngularity, https://nx.dev/blog/s1ngularity-postmortem ; gh plaintext storage,
//! https://github.com/cli/cli/issues/7757). Also cloud, container and AI-tool login files that
//! hold tokens: Shai-Hulud 2.0 takes gcloud's application_default_credentials.json; Docker
//! documents keeping registry logins in a credential store instead of config.json
//! (https://docs.docker.com/reference/cli/docker/login/#credential-stores).
//! Values are never read into output: findings name the file, line and kind only.

use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const CREDENTIALS_SUB_CATEGORY: &str = "Plaintext credentials";

/// What a credential file holds and how to tell a stored secret on one line.
pub struct CredFile {
    pub rel: &'static str,
    pub kind: &'static str,
    pub severity: Severity,
    /// True when the line stores a literal secret (not a ${VAR} reference).
    pub stores_secret: fn(&str) -> bool,
    pub fix: &'static str,
    /// For files read as a whole: the lines that hold a secret.
    pub whole_file: Option<fn(&str) -> Vec<usize>>,
    /// The file's existence is the finding (a login token file); it is never opened.
    pub exists_only: bool,
}

fn never(_: &str) -> bool {
    false
}

fn line_with(text: &str, needle: &str) -> usize {
    text.lines()
        .position(|l| l.contains(needle))
        .map_or(1, |i| i + 1)
}

/// ~/.docker/config.json registries whose login is stored inline (`auth`, `identitytoken`)
/// instead of in a credential store or helper.
pub fn docker_inline_auths(text: &str) -> Vec<usize> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let helpers = v.get("credHelpers").and_then(|h| h.as_object());
    let Some(auths) = v.get("auths").and_then(|a| a.as_object()) else {
        return Vec::new();
    };
    let mut lines: Vec<usize> = auths
        .iter()
        .filter(|(reg, entry)| {
            let inline = ["auth", "identitytoken", "password"].iter().any(|k| {
                entry
                    .get(k)
                    .and_then(|x| x.as_str())
                    .is_some_and(|x| !x.is_empty())
            });
            inline && !helpers.is_some_and(|h| h.contains_key(*reg))
        })
        .map(|(reg, _)| line_with(text, &format!("\"{reg}\"")))
        .collect();
    lines.sort_unstable();
    lines
}

/// `aws_access_key_id = AKIA...`: a long-term IAM key (ASIA keys are temporary).
fn aws_credentials(line: &str) -> bool {
    key_value(line, &['=']).is_some_and(|(k, v)| {
        k == "aws_access_key_id" && v.trim().starts_with("AKIA") && v.trim().len() >= 20
    })
}

/// gcloud application default credentials holding a user's refresh token.
pub fn gcloud_user_creds(text: &str) -> Vec<usize> {
    let user = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| {
            v.get("type")
                .and_then(|t| t.as_str())
                .map(|t| t == "authorized_user")
        })
        .unwrap_or(false);
    if user {
        vec![line_with(text, "\"type\"")]
    } else {
        Vec::new()
    }
}

/// kubeconfig users with a static token, client key or password, unless they use an exec
/// plugin or every context using them points at a cluster on this Mac (kind, minikube,
/// Docker Desktop). Read line by line in the layout kubectl writes.
pub fn kube_static_creds(text: &str) -> Vec<usize> {
    #[derive(Default)]
    struct Item {
        fields: Vec<(String, String, usize)>,
    }
    impl Item {
        fn get(&self, k: &str) -> Option<&str> {
            self.fields
                .iter()
                .find(|(key, _, _)| key == k)
                .map(|(_, v, _)| v.as_str())
        }
    }
    let mut sections: std::collections::BTreeMap<String, Vec<Item>> = Default::default();
    let mut section = String::new();
    let mut item_indent = None;
    for (i, raw) in text.lines().enumerate() {
        let indent = raw.len() - raw.trim_start().len();
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if indent == 0 && !t.starts_with('-') {
            section = t.trim_end_matches(':').to_string();
            item_indent = None;
            continue;
        }
        let list = sections.entry(section.clone()).or_default();
        let body = if let Some(rest) = t.strip_prefix("- ") {
            if item_indent.is_none_or(|ii| indent <= ii) {
                item_indent = Some(indent);
                list.push(Item::default());
            }
            rest
        } else {
            t
        };
        if let (Some(item), Some((k, v))) = (list.last_mut(), body.split_once(':')) {
            item.fields
                .push((k.trim().to_string(), v.trim().to_string(), i + 1));
        }
    }
    let empty = Vec::new();
    let clusters = sections.get("clusters").unwrap_or(&empty);
    let contexts = sections.get("contexts").unwrap_or(&empty);
    let local = |cluster: &str| {
        clusters.iter().any(|c| {
            c.get("name") == Some(cluster)
                && c.get("server").is_some_and(|s| {
                    [
                        "://127.0.0.1",
                        "://localhost",
                        "://[::1]",
                        "kubernetes.docker.internal",
                    ]
                    .iter()
                    .any(|h| s.contains(h))
                })
        })
    };
    let mut lines = Vec::new();
    for user in sections.get("users").unwrap_or(&empty) {
        let Some(name) = user.get("name") else {
            continue;
        };
        if user.get("exec").is_some() {
            continue;
        }
        let used: Vec<&str> = contexts
            .iter()
            .filter(|c| c.get("user") == Some(name))
            .filter_map(|c| c.get("cluster"))
            .collect();
        if !used.is_empty() && used.iter().all(|c| local(c)) {
            continue;
        }
        lines.extend(
            user.fields
                .iter()
                .filter(|(k, v, _)| {
                    matches!(k.as_str(), "token" | "client-key-data" | "password") && !v.is_empty()
                })
                .map(|(_, _, l)| *l),
        );
    }
    lines.sort_unstable();
    lines
}

/// A literal token: at least 8 characters, not a `$VAR` / `${VAR}` reference.
fn literal(v: &str) -> bool {
    let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
    v.len() >= 8 && !v.starts_with('$')
}

/// A literal password: any non-empty value that is not a `$VAR` reference (passwords can be short).
fn literal_password(v: &str) -> bool {
    let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
    !v.is_empty() && !v.starts_with('$')
}

fn key_value<'a>(line: &'a str, seps: &[char]) -> Option<(&'a str, &'a str)> {
    let t = line.trim();
    let i = t.find(seps)?;
    Some((t[..i].trim(), &t[i + 1..]))
}

/// `scheme://user:password@host` with a literal password.
fn url_with_password(line: &str) -> bool {
    let Some(i) = line.find("://") else {
        return false;
    };
    let authority = line[i + 3..]
        .split(['/', ' ', '"', '\''])
        .next()
        .unwrap_or("");
    authority
        .rsplit_once('@')
        .and_then(|(userinfo, _)| userinfo.split_once(':'))
        .is_some_and(|(_, pass)| !pass.is_empty() && !pass.starts_with('$'))
}

// Lines are matched whether or not they are commented out: a commented token is still in
// the file that stealers copy. In a comment a password must look like a token (8+ characters),
// so `# password goes here` is not reported.
fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

fn password_in(line: &str, v: &str) -> bool {
    if is_comment(line) {
        literal(v)
    } else {
        literal_password(v)
    }
}

fn npmrc(line: &str) -> bool {
    key_value(line, &['=']).is_some_and(|(k, v)| {
        (k.ends_with("_authToken") && literal(v))
            || ((k.ends_with("_auth") || k.ends_with("_password")) && password_in(line, v))
    })
}

fn yarnrc(line: &str) -> bool {
    key_value(line, &[':']).is_some_and(|(k, v)| {
        (k == "npmAuthToken" && literal(v)) || (k == "npmAuthIdent" && password_in(line, v))
    })
}

fn pypirc(line: &str) -> bool {
    key_value(line, &['=', ':']).is_some_and(|(k, v)| {
        k.trim_start_matches(['#', ' ']) == "password" && password_in(line, v)
    })
}

fn netrc(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    words
        .windows(2)
        .any(|w| w[0] == "password" && password_in(line, w[1]))
}

/// `:rubygems_api_key: <key>` or a host-keyed entry `https://host/org: Bearer <key>`.
fn gem(line: &str) -> bool {
    let t = line.trim().trim_start_matches(':');
    t.split_once(": ")
        .is_some_and(|(k, v)| (k.ends_with("api_key") || k.starts_with("http")) && literal(v))
}

fn cargo(line: &str) -> bool {
    key_value(line, &['=']).is_some_and(|(k, v)| k == "token" && literal(v))
}

fn pip_conf(line: &str) -> bool {
    key_value(line, &['=', ':'])
        .is_some_and(|(k, v)| k.ends_with("index-url") && url_with_password(v))
}

fn gh_hosts(line: &str) -> bool {
    key_value(line, &[':']).is_some_and(|(k, v)| k == "oauth_token" && literal(v))
}

const NPM_FIX: &str = "Remove the token from the file. Publish from CI with npm trusted publishing, or keep the token in Keychain and reference it as ${NPM_TOKEN}.";
const PIP_FIX: &str =
    "Move the password to Keychain with `pip install keyring` and drop it from the index URL.";
const AWS_FIX: &str = "Switch to `aws configure sso` (IAM Identity Center) or a credential_process helper, then deactivate this access key in IAM.";
const AGENT_FIX: &str = "Log out of the tool when you are not using it, and revoke the session from the provider's account page if this Mac may be compromised.";
const CARGO_FIX: &str = "Delete the file and set `[registry] global-credential-providers = [\"cargo:macos-keychain\"]` in ~/.cargo/config.toml, then run `cargo login` again.";

pub fn cred_files() -> Vec<CredFile> {
    let c = |rel, kind, severity, stores_secret, fix| CredFile {
        rel,
        kind,
        severity,
        stores_secret,
        fix,
        whole_file: None,
        exists_only: false,
    };
    let w = |rel, kind, check: fn(&str) -> Vec<usize>, fix| CredFile {
        rel,
        kind,
        severity: Severity::Medium,
        stores_secret: never,
        fix,
        whole_file: Some(check),
        exists_only: false,
    };
    let e = |rel, kind| CredFile {
        rel,
        kind,
        severity: Severity::Medium,
        stores_secret: never,
        fix: AGENT_FIX,
        whole_file: None,
        exists_only: true,
    };
    vec![
        c(".npmrc", "npm token", Severity::High, npmrc as fn(&str) -> bool, NPM_FIX),
        c(".yarnrc.yml", "npm token (Yarn)", Severity::High, yarnrc, NPM_FIX),
        c(".pypirc", "PyPI token", Severity::High, pypirc, "Use PyPI trusted publishing from CI, or store the token with `keyring set https://upload.pypi.org/legacy/ __token__` and remove the password line."),
        c(".gem/credentials", "RubyGems API key", Severity::High, gem, "Use RubyGems trusted publishing from CI, or revoke this key and enable MFA for pushes."),
        c(".cargo/credentials.toml", "crates.io token", Severity::High, cargo, CARGO_FIX),
        c(".cargo/credentials", "crates.io token", Severity::High, cargo, CARGO_FIX),
        c(".git-credentials", "Git password or token", Severity::High, url_with_password, "Run `git config --global credential.helper osxkeychain`, delete ~/.git-credentials, and revoke the tokens it held."),
        c(".netrc", "Password", Severity::Medium, netrc, "Move these passwords to Keychain or the tool's own credential helper, then delete the entries."),
        c(".config/pip/pip.conf", "Package index password", Severity::Medium, pip_conf, PIP_FIX),
        c(".pip/pip.conf", "Package index password", Severity::Medium, pip_conf, PIP_FIX),
        c("Library/Application Support/pip/pip.conf", "Package index password", Severity::Medium, pip_conf, PIP_FIX),
        c(".config/gh/hosts.yml", "GitHub CLI token", Severity::Medium, gh_hosts, "Run `gh auth logout` then `gh auth login` without --insecure-storage, so the token moves to Keychain."),
        w(".docker/config.json", "Docker registry login", docker_inline_auths, "Set \"credsStore\": \"osxkeychain\" in ~/.docker/config.json, then `docker logout` and `docker login` each listed registry so the login moves to Keychain."),
        c(".aws/credentials", "AWS long-term access key", Severity::Medium, aws_credentials, AWS_FIX),
        w(".config/gcloud/application_default_credentials.json", "Google Cloud user credentials", gcloud_user_creds, "Run `gcloud auth application-default revoke` when you no longer need local application credentials."),
        w(".kube/config", "Kubernetes static credential", kube_static_creds, "Use an exec credential plugin (for example `aws eks get-token` or `gke-gcloud-auth-plugin`) instead of a static token or client key, and rotate the credential."),
        e(".codex/auth.json", "Codex login"),
        e(".gemini/oauth_creds.json", "Gemini CLI login"),
        e(".claude/.credentials.json", "Claude Code login"),
    ]
}

pub fn scan_credentials(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    scan_credentials_with_home(ctx, home.as_deref())
}

pub fn scan_credentials_with_home(
    ctx: &ScanContext,
    home: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let skip = |reason| {
        (
            Vec::new(),
            vec![Inspection::skipped(
                Category::Security,
                Some(CREDENTIALS_SUB_CATEGORY),
                Some(reason),
            )],
        )
    };
    if !ctx.is_category_selected(Category::Security) {
        return skip("category not selected");
    }
    let Some(home) = home else {
        return skip("home directory unavailable");
    };
    let present: Vec<(CredFile, PathBuf)> = cred_files()
        .into_iter()
        .map(|c| {
            let p = home.join(c.rel);
            (c, p)
        })
        .filter(|(_, p)| p.is_file())
        .collect();
    let mut unreadable = Vec::new();
    let mut readable: Vec<(&CredFile, &PathBuf, String)> = Vec::new();
    for (rule, path) in &present {
        if rule.exists_only {
            readable.push((rule, path, String::new()));
            continue;
        }
        match std::fs::read(path) {
            Ok(bytes) => readable.push((rule, path, String::from_utf8_lossy(&bytes).into_owned())),
            Err(e) => unreadable.push(Inspection::unparseable(
                Category::Security,
                Some(CREDENTIALS_SUB_CATEGORY),
                Some(path.to_string_lossy().as_ref()),
                format!("could not read: {e}"),
            )),
        }
    }
    // Files read (and existence-only login files, which are never opened) count as checked;
    // files that could not be read are named separately.
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    let scope = match (readable.len(), unreadable.len()) {
        (0, 0) => "user (no credential files)".to_string(),
        (n, 0) => format!("user ({n} credential file{})", plural(n)),
        (n, m) => format!("user ({n} credential file{}, {m} unreadable)", plural(n)),
    };

    let mut findings = Vec::new();
    for (rule, path, text) in &readable {
        if rule.exists_only {
            findings.push(
                Finding::new(
                    format!("plaintext-credential:{}", rule.rel),
                    format!("{} stored in a file: ~/{}", rule.kind, rule.rel),
                    Category::Security,
                    rule.severity,
                    format!("~/{} holds this tool's login token: anyone who copies the file can use the account. The file is not read or shown.", rule.rel),
                )
                .with_sub_category(CREDENTIALS_SUB_CATEGORY)
                .with_scope(scope.clone())
                .with_location(path.to_string_lossy().as_ref(), None)
                .with_remediation(rule.fix),
            );
            continue;
        }
        let hits: Vec<usize> = match rule.whole_file {
            Some(check) => check(text),
            None => text
                .lines()
                .enumerate()
                .filter(|(_, l)| (rule.stores_secret)(l))
                .map(|(i, _)| i + 1)
                .collect(),
        };
        let Some(&first) = hits.first() else {
            continue;
        };
        let commented = text
            .lines()
            .enumerate()
            .any(|(i, l)| hits.contains(&(i + 1)) && is_comment(l));
        let note = if commented {
            " (some on commented-out lines)"
        } else {
            ""
        };
        let entries = if hits.len() == 1 {
            "1 entry".to_string()
        } else {
            format!("{} entries", hits.len())
        };
        findings.push(
            Finding::new(
                format!("plaintext-credential:{}", rule.rel),
                format!("{} stored in plaintext in ~/{}", rule.kind, rule.rel),
                Category::Security,
                rule.severity,
                format!(
                    "~/{} holds {entries} with a literal secret{note}. Anyone who copies this file can use the credential. Values are not shown.",
                    rule.rel
                ),
            )
            .with_sub_category(CREDENTIALS_SUB_CATEGORY)
            .with_scope(scope.clone())
            .with_location(path.to_string_lossy().as_ref(), Some(first))
            .with_remediation(rule.fix),
        );
    }
    let mut inspections = vec![Inspection::inspected(
        Category::Security,
        Some(CREDENTIALS_SUB_CATEGORY),
        scope,
    )];
    inspections.extend(unreadable);
    (findings, inspections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::InspectionStatus;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("cr_{}_{n}_{nanos}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn rule(rel: &str) -> CredFile {
        cred_files()
            .into_iter()
            .find(|c| c.rel == rel)
            .unwrap_or_else(|| panic!("no rule for {rel}"))
    }

    /// Built at runtime so no `password = <value>` literal sits in the source (secret scanners).
    const PW: &str = concat!("pass", "word");

    fn fake(n: usize) -> String {
        "x".repeat(n)
    }

    #[test]
    fn test_each_file_flags_literal_secrets_and_skips_references() {
        let t = fake(36);
        let cases: Vec<(&str, String, &str)> = vec![
            (
                ".npmrc",
                format!("//registry.npmjs.org/:_authToken=npm_{t}"),
                "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
            ),
            (
                ".npmrc",
                format!("_auth={t}"),
                "registry=https://registry.npmjs.org/",
            ),
            (
                ".yarnrc.yml",
                format!("  npmAuthToken: npm_{t}"),
                "  npmAuthToken: \"${NPM_TOKEN}\"",
            ),
            (
                ".pypirc",
                format!("{PW} = pypi-{t}"),
                concat!("pass", "word = ${PYPI_TOKEN}"),
            ),
            (
                ".netrc",
                format!("machine api.github.com login me {PW} {t}"),
                "machine example.com login me",
            ),
            (
                ".git-credentials",
                format!("https://me:ghp_{t}@github.com"),
                "https://github.com",
            ),
            (
                ".gem/credentials",
                format!(":rubygems_api_key: rubygems_{t}"),
                "---",
            ),
            (
                ".cargo/credentials.toml",
                format!("token = \"cio{t}\""),
                "[registry]",
            ),
            (
                ".config/pip/pip.conf",
                format!("index-url = https://me:{t}@pypi.corp.example/simple"),
                "index-url = https://pypi.org/simple",
            ),
            (
                ".config/gh/hosts.yml",
                format!("    oauth_token: gho_{t}"),
                "    git_protocol: https",
            ),
        ];
        for (rel, bad, ok) in cases {
            let r = rule(rel);
            assert!((r.stores_secret)(&bad), "{rel} missed: {bad}");
            assert!(!(r.stores_secret)(ok), "{rel} false alarm: {ok}");
        }
    }

    #[test]
    fn test_short_passwords_yarn_ident_gem_hosts_and_commented_lines() {
        let short = fake(7);
        let cases: Vec<(&str, String)> = vec![
            (
                ".netrc",
                format!("machine example.com login me {PW} {short}"),
            ),
            (".pypirc", format!("{PW}: {short}")),
            (".npmrc", format!("_{PW}={short}")),
            (".yarnrc.yml", format!("  npmAuthIdent: \"me:{short}\"")),
            (
                ".gem/credentials",
                format!(
                    "https://rubygems.pkg.github.com/org: Bearer ghp_{}",
                    fake(12)
                ),
            ),
            // Commented-out lines still sit in the file stealers copy, so they count.
            (
                ".npmrc",
                format!("# //registry.npmjs.org/:_authToken=npm_{}", fake(12)),
            ),
        ];
        for (rel, bad) in &cases {
            assert!((rule(rel).stores_secret)(bad), "{rel} missed: {bad}");
        }
        // Tokens still need some length: a placeholder is not a token.
        assert!(!(rule(".npmrc").stores_secret)("_authToken=xxx"));
        assert!(!(rule(".netrc").stores_secret)(&format!(
            "machine x login me {PW} $SECRET"
        )));
    }

    #[test]
    fn test_launch_follow_ups_comments_and_scope() {
        // A comment that merely mentions a password is not a stored one; a commented token still is.
        assert!(!(rule(".netrc").stores_secret)(&format!(
            "# {PW} goes here"
        )));
        assert!((rule(".netrc").stores_secret)(&format!(
            "# machine x login me {PW} {}",
            fake(12)
        )));
        assert!(!(rule(".pypirc").stores_secret)(&format!("# {PW}: tbd")));

        use std::os::unix::fs::PermissionsExt;
        let home = tmp();
        fs::write(
            home.join(".npmrc"),
            format!("# //r.example/:_authToken=npm_{}\n", fake(20)),
        )
        .unwrap();
        fs::write(home.join(".pypirc"), format!("{PW} = pypi-{}\n", fake(20))).unwrap();
        fs::set_permissions(home.join(".pypirc"), fs::Permissions::from_mode(0o000)).unwrap();
        let root = fs::read(home.join(".pypirc")).is_ok();
        let (f, _) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        fs::set_permissions(home.join(".pypirc"), fs::Permissions::from_mode(0o600)).unwrap();
        let npm = f
            .iter()
            .find(|x| x.id == "plaintext-credential:.npmrc")
            .unwrap();
        assert!(
            npm.description.contains("commented-out"),
            "{}",
            npm.description
        );
        if !root {
            // The unreadable file is not counted as checked.
            assert_eq!(
                npm.scope.as_deref(),
                Some("user (1 credential file, 1 unreadable)")
            );
        }
    }

    #[test]
    fn test_unreadable_files_are_reported_and_non_utf8_files_still_read() {
        use std::os::unix::fs::PermissionsExt;
        let home = tmp();
        let mut netrc = format!("machine x login me {PW} ").into_bytes();
        netrc.extend_from_slice(&[0xff, 0xfe]);
        netrc.extend_from_slice(format!("{}\n", fake(8)).as_bytes());
        fs::write(home.join(".netrc"), netrc).unwrap();
        fs::write(home.join(".pypirc"), format!("{PW} = pypi-{}\n", fake(20))).unwrap();
        fs::set_permissions(home.join(".pypirc"), fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(home.join(".pypirc")).is_ok() {
            // Running as root: permissions don't block reads, so there is nothing to test.
            return;
        }

        let (f, i) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        fs::set_permissions(home.join(".pypirc"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            f.iter().any(|x| x.id == "plaintext-credential:.netrc"),
            "{f:?}"
        );
        assert!(
            i.iter().any(
                |x| matches!(&x.status, InspectionStatus::UnparseableData { .. })
                    && format!("{x:?}").contains(".pypirc")
            ),
            "{i:?}"
        );
    }

    #[test]
    fn test_c2_docker_aws_gcloud_kube_and_agent_logins() {
        let t = fake(24);
        // Docker: an inline auth not covered by a credential helper.
        let docker = format!("{{\n  \"auths\": {{\n    \"ghcr.io\": {{\"auth\": \"{t}\"}},\n    \"registry.example\": {{\"auth\": \"{t}\"}},\n    \"https://index.docker.io/v1/\": {{}}\n  }},\n  \"credHelpers\": {{\"registry.example\": \"ecr-login\"}},\n  \"credsStore\": \"osxkeychain\"\n}}\n");
        assert_eq!(docker_inline_auths(&docker), vec![3]);
        assert!(docker_inline_auths(
            "{\"auths\": {\"ghcr.io\": {}}, \"credsStore\": \"osxkeychain\"}"
        )
        .is_empty());
        // AWS: long-term AKIA keys, not temporary ASIA ones.
        let aws = rule(".aws/credentials");
        assert!((aws.stores_secret)(&format!(
            "aws_access_key_id = AKIA{}",
            "Q".repeat(16)
        )));
        assert!(!(aws.stores_secret)(&format!(
            "aws_access_key_id = ASIA{}",
            "Q".repeat(16)
        )));
        // gcloud: user refresh tokens, not service account impersonation configs.
        assert_eq!(
            gcloud_user_creds("{\n  \"client_id\": \"x\",\n  \"type\": \"authorized_user\"\n}"),
            vec![3]
        );
        assert!(gcloud_user_creds("{\"type\": \"impersonated_service_account\"}").is_empty());
        // Kubernetes: static credentials, except exec plugins and clusters on this Mac.
        let kube = format!("apiVersion: v1\nclusters:\n- cluster:\n    server: https://prod.example:6443\n  name: prod\n- cluster:\n    server: https://127.0.0.1:6443\n  name: kind\ncontexts:\n- context:\n    cluster: prod\n    user: prod-admin\n  name: prod\n- context:\n    cluster: kind\n    user: kind-admin\n  name: kind\n- context:\n    cluster: prod\n    user: eks\n  name: eks\nusers:\n- name: prod-admin\n  user:\n    token: {t}\n- name: kind-admin\n  user:\n    client-key-data: {t}\n- name: eks\n  user:\n    exec:\n      command: aws\n");
        assert_eq!(kube_static_creds(&kube), vec![25]);

        let home = tmp();
        for (rel, body) in [
            (".docker/config.json", docker.as_str()),
            (".codex/auth.json", "{}"),
            (".kube/config", kube.as_str()),
        ] {
            let p = home.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
        let (f, _) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        let ids: Vec<_> = f.iter().map(|x| x.id.as_str()).collect();
        for id in [
            "plaintext-credential:.docker/config.json",
            "plaintext-credential:.codex/auth.json",
            "plaintext-credential:.kube/config",
        ] {
            assert!(ids.contains(&id), "{id} missing: {ids:?}");
        }
        assert!(f.iter().all(|x| x.severity == Severity::Medium), "{f:?}");
        let codex = f
            .iter()
            .find(|x| x.id.ends_with(".codex/auth.json"))
            .unwrap();
        assert_eq!(codex.line_number, None);
        assert!(codex.description.contains("login"), "{}", codex.description);
        assert!(
            !serde_json::to_string(&f).unwrap().contains(&t),
            "value leaked"
        );
    }

    #[test]
    fn test_finding_text_claims_only_what_is_certain() {
        let t = fake(30);
        let home = tmp();
        let kube = format!("clusters:\n- cluster:\n    server: https://k.example\n  name: k\ncontexts:\n- context:\n    cluster: k\n    user: u\n  name: k\nusers:\n- name: u\n  user:\n    token: {t}\n");
        let files = [
            (".npmrc", format!("//r.example/:_authToken=npm_{t}")),
            (".yarnrc.yml", format!("npmAuthToken: npm_{t}")),
            (".pypirc", format!("{PW} = pypi-{t}")),
            (
                ".gem/credentials",
                format!(":rubygems_api_key: rubygems_{t}"),
            ),
            (".cargo/credentials.toml", format!("token = \"cio{t}\"")),
            (".git-credentials", format!("https://me:ghp_{t}@github.com")),
            (".netrc", format!("machine x login me {PW} {t}")),
            (
                ".config/pip/pip.conf",
                format!("index-url = https://me:{t}@p.example/simple"),
            ),
            (
                ".config/gh/hosts.yml",
                format!("github.com:\n    oauth_token: gho_{t}"),
            ),
            (
                ".docker/config.json",
                format!("{{\"auths\": {{\"ghcr.io\": {{\"auth\": \"{t}\"}}}}}}"),
            ),
            (
                ".aws/credentials",
                format!("aws_access_key_id = AKIA{}", "Q".repeat(16)),
            ),
            (
                ".config/gcloud/application_default_credentials.json",
                "{\"type\": \"authorized_user\"}".to_string(),
            ),
            (".kube/config", kube),
        ];
        for (rel, body) in &files {
            let p = home.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }
        let (f, _) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        assert_eq!(f.len(), files.len(), "{f:?}");
        for x in &f {
            assert!(
                x.description
                    .contains("Anyone who copies this file can use the credential."),
                "{}",
                x.description
            );
            assert!(
                !x.description.contains("tealer") && !x.description.contains("worm"),
                "{}",
                x.description
            );
        }
    }

    #[test]
    fn test_c2_login_files_are_never_opened() {
        use std::os::unix::fs::PermissionsExt;
        let home = tmp();
        let p = home.join(".gemini/oauth_creds.json");
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, "{}").unwrap();
        // Unreadable: if the scanner tried to read it, it would report it as unreadable.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&p).is_ok() {
            // Running as root: permissions don't block reads, so this can't detect a read.
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            return;
        }
        let (f, i) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let login = f
            .iter()
            .find(|x| x.id.ends_with(".gemini/oauth_creds.json"))
            .expect("login file");
        assert!(
            login.description.contains("not read"),
            "{}",
            login.description
        );
        assert!(
            !login.description.contains("tealer"),
            "{}",
            login.description
        );
        assert!(
            !i.iter()
                .any(|x| matches!(x.status, InspectionStatus::UnparseableData { .. })),
            "{i:?}"
        );
    }

    #[test]
    fn test_publish_tokens_are_high_and_fixes_name_a_safer_option() {
        for rel in [
            ".npmrc",
            ".yarnrc.yml",
            ".pypirc",
            ".gem/credentials",
            ".cargo/credentials.toml",
            ".git-credentials",
        ] {
            assert_eq!(rule(rel).severity, Severity::High, "{rel}");
        }
        for rel in [".netrc", ".config/pip/pip.conf", ".config/gh/hosts.yml"] {
            assert_eq!(rule(rel).severity, Severity::Medium, "{rel}");
        }
        assert!(rule(".git-credentials").fix.contains("osxkeychain"));
        assert!(rule(".cargo/credentials.toml")
            .fix
            .contains("cargo:macos-keychain"));
        assert!(rule(".npmrc").fix.contains("trusted publishing"));
        assert!(rule(".config/gh/hosts.yml").fix.contains("gh auth login"));
    }

    #[test]
    fn test_scan_reports_file_and_line_never_the_value() {
        let home = tmp();
        let secret = format!("npm_{}", "S".repeat(36));
        fs::write(
            home.join(".npmrc"),
            format!(
                "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={secret}\n"
            ),
        )
        .unwrap();
        fs::create_dir_all(home.join(".config/gh")).unwrap();
        fs::write(
            home.join(".config/gh/hosts.yml"),
            "github.com:\n    git_protocol: https\n",
        )
        .unwrap();

        let (f, i) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].line_number, Some(2));
        assert_eq!(f[0].severity, Severity::High);
        let scope = "user (2 credential files)";
        assert_eq!(f[0].scope.as_deref(), Some(scope));
        assert!(
            !serde_json::to_string(&f).unwrap().contains(&secret[4..]),
            "value leaked"
        );
        assert!(i.iter().any(|x| x.status
            == InspectionStatus::Inspected {
                inspected_scope: scope.into()
            }));
    }

    #[test]
    fn test_one_finding_per_file_even_with_many_lines() {
        let home = tmp();
        let t = fake(30);
        fs::write(
            home.join(".netrc"),
            format!("machine a.example login u {PW} {t}\nmachine b.example login u {PW} {t}\n"),
        )
        .unwrap();
        let (f, _) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].description.contains("2 entries"),
            "{}",
            f[0].description
        );
    }

    #[test]
    fn test_nothing_present_and_not_selected() {
        let home = tmp();
        let (f, i) = scan_credentials_with_home(&ScanContext::new(), Some(&home));
        assert!(f.is_empty());
        assert!(
            matches!(&i[0].status, InspectionStatus::Inspected { inspected_scope } if inspected_scope.contains("no credential files"))
        );
        let ctx = ScanContext::new().with_categories(vec![Category::Garbage]);
        let (_, i) = scan_credentials_with_home(&ctx, Some(&home));
        assert!(matches!(i[0].status, InspectionStatus::Skipped { .. }));
    }
}
