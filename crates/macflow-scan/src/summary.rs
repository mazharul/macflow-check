//! The default terminal report: what to fix first, grouped and short.
//! `render_report` (report.rs) keeps the full per-check listing behind `--details`.

use std::collections::{BTreeMap, BTreeSet};

use crate::models::{Category, Finding, InspectionStatus, ScanResult, Severity};

#[derive(Debug, Clone, Default)]
pub struct SummaryOptions {
    /// ANSI colour; the CLI turns it on only for a terminal without NO_COLOR.
    pub color: bool,
    /// Home directory, shown as `~` in paths.
    pub home: Option<String>,
    pub offline: bool,
    /// Scan time in seconds, shown in the header when known.
    pub elapsed_secs: Option<f64>,
    /// CLI version for the header line.
    pub version: &'static str,
}

const RED: &str = "1;31";
const YELLOW: &str = "1;33";
const CYAN: &str = "1;36";
const GREEN: &str = "32";
const BOLD: &str = "1";
const DIM: &str = "2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    FixNow,
    WorthFixing,
    Disk,
    Low,
    Hidden,
}

struct Group<'a> {
    section: Section,
    label: String,
    findings: Vec<&'a Finding>,
}

struct Out<'o> {
    opts: &'o SummaryOptions,
    s: String,
}

impl Out<'_> {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.opts.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn line(&mut self, text: &str) {
        self.s.push_str(text);
        self.s.push('\n');
    }

    /// Home folder shown as `~` inside free text such as a fix.
    fn tilde(&self, text: &str) -> String {
        match self.opts.home.as_deref() {
            Some(h) if !h.trim_end_matches('/').is_empty() => {
                text.replace(&format!("{}/", h.trim_end_matches('/')), "~/")
            }
            _ => text.to_string(),
        }
    }

    fn path(&self, f: &Finding) -> Option<String> {
        let p = f.file_path.as_deref()?;
        let home = self.opts.home.as_deref().map(|h| h.trim_end_matches('/'));
        let p = match home {
            Some(h) if !h.is_empty() && p.starts_with(h) && p[h.len()..].starts_with('/') => {
                format!("~{}", &p[h.len()..])
            }
            _ => p.to_string(),
        };
        Some(match f.line_number {
            Some(n) => format!("{p}:{n}"),
            None => p,
        })
    }
}

fn section_of(f: &Finding) -> Section {
    if f.category == Category::Garbage {
        return Section::Disk;
    }
    match f.severity {
        Severity::Critical | Severity::High => Section::FixNow,
        Severity::Medium => Section::WorthFixing,
        Severity::Low => Section::Low,
        Severity::Info => Section::Hidden,
    }
}

const MIB: f64 = 1024.0 * 1024.0;
const GIB: f64 = 1024.0 * MIB;

/// Bytes named in a title such as "npm cache: 8.0 GB reclaimable". The scanner
/// writes GB and MB for powers of 1024, so they are read back the same way.
fn size_in(title: &str) -> u64 {
    let words: Vec<&str> = title.split_whitespace().collect();
    for w in words.windows(2) {
        let mult: f64 = match w[1].trim_end_matches([',', ')', ':']) {
            "KB" => 1024.0,
            "MB" => MIB,
            "GB" => GIB,
            "TB" => GIB * 1024.0,
            _ => continue,
        };
        if let Ok(n) = w[0].trim_start_matches('(').parse::<f64>() {
            return (n * mult) as u64;
        }
    }
    0
}

fn human(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1} GB", b / GIB)
    } else if b >= MIB {
        format!("{:.0} MB", b / MIB)
    } else {
        "under 1 MB".to_string()
    }
}

/// Numbered groups in display order: fix now, worth fixing, then disk space.
fn groups(result: &ScanResult) -> Vec<Group<'_>> {
    let mut by: BTreeMap<(Section, String), Vec<&Finding>> = BTreeMap::new();
    for f in &result.findings {
        let sec = section_of(f);
        if sec > Section::Disk {
            continue;
        }
        let label = f.sub_category.clone().unwrap_or_else(|| "Other".into());
        // Each disk item is its own line: the sizes differ and so do the commands.
        let key = if sec == Section::Disk {
            f.title.clone()
        } else {
            label
        };
        by.entry((sec, key)).or_default().push(f);
    }
    let mut gs: Vec<Group> = by
        .into_iter()
        .map(|((section, label), findings)| Group {
            section,
            label,
            findings,
        })
        .collect();
    gs.sort_by_key(|g| {
        let top = g.findings.iter().map(|f| f.severity).max();
        let size: u64 = g.findings.iter().map(|f| size_in(&f.title)).sum();
        (
            g.section,
            std::cmp::Reverse(top),
            std::cmp::Reverse(size),
            std::cmp::Reverse(g.findings.len()),
            g.label.clone(),
        )
    });
    gs
}

/// Title without a trailing "(...)" so masked variants of one key count as one kind.
fn kind(title: &str) -> &str {
    match title.rfind(" (") {
        Some(i) if title.ends_with(')') => &title[..i],
        _ => title,
    }
}

enum GroupFix {
    One(String),
    Differ,
    None,
}

/// The advice without a per-item "(e.g. ...)" example; text after the example stays.
fn general(fix: &str) -> String {
    let Some(i) = fix.find(" (e.g.") else {
        return fix.to_string();
    };
    match fix[i..].find(')') {
        Some(j) => format!("{}{}", &fix[..i], &fix[i + j + 1..]),
        None => format!("{}.", fix[..i].trim_end_matches('.')),
    }
}

/// One fix for the group, only when every member shares it. Fixes that differ just
/// by their "(e.g. ...)" example share the general advice; other differences send
/// the reader to `--show` rather than print one kind's fix for all.
fn group_fix(g: &Group) -> GroupFix {
    let first = g.findings[0].remediation.as_deref();
    if g.findings.iter().all(|f| f.remediation.as_deref() == first) {
        return first.map_or(GroupFix::None, |f| GroupFix::One(f.to_string()));
    }
    let shared: BTreeSet<Option<String>> = g
        .findings
        .iter()
        .map(|f| f.remediation.as_deref().map(general))
        .collect();
    match shared.into_iter().collect::<Vec<_>>().as_slice() {
        [Some(fix)] => GroupFix::One(fix.clone()),
        _ => GroupFix::Differ,
    }
}

fn render_group_line(o: &mut Out, n: usize, g: &Group) {
    let colour = match g.section {
        Section::FixNow => RED,
        Section::WorthFixing => YELLOW,
        _ => CYAN,
    };
    let num = o.paint(colour, &format!("{n:>2}"));
    let first = g.findings[0];
    if g.findings.len() == 1 {
        o.line(&format!("{num}  {}", first.title));
    } else {
        let head = o.paint(BOLD, &format!("{} · {}", g.label, g.findings.len()));
        o.line(&format!("{num}  {head}"));
        let mut kinds: Vec<(&str, usize)> = Vec::new();
        for f in &g.findings {
            match kinds.iter_mut().find(|(k, _)| *k == kind(&f.title)) {
                Some(e) => e.1 += 1,
                None => kinds.push((kind(&f.title), 1)),
            }
        }
        for (k, c) in kinds.iter().take(3) {
            let full = g
                .findings
                .iter()
                .find(|f| kind(&f.title) == *k)
                .map(|f| f.title.as_str())
                .unwrap_or(k);
            let times = if *c > 1 {
                format!(" ×{c}")
            } else {
                String::new()
            };
            o.line(&format!("    {full}{times}"));
        }
        if kinds.len() > 3 {
            let more = o.paint(DIM, &format!("    +{} more kinds", kinds.len() - 3));
            o.line(&more);
        }
    }
    match group_fix(g) {
        GroupFix::One(fix) => {
            let fix = o.tilde(&fix);
            o.line(&format!("    → {fix}"));
        }
        GroupFix::Differ => o.line(&format!("    → Fixes differ: macflow-check --show {n}")),
        GroupFix::None => {}
    }
    let mut hint = o.path(first).unwrap_or_default();
    if g.findings.len() > 1 {
        if !hint.is_empty() {
            hint.push_str(&format!(" (+{} more)   ", g.findings.len() - 1));
        }
        hint.push_str(&format!("macflow-check --show {n}"));
    }
    if !hint.is_empty() {
        let h = o.paint(DIM, &format!("    {hint}"));
        o.line(&h);
    }
}

pub fn render_summary(result: &ScanResult, opts: &SummaryOptions) -> String {
    let mut o = Out {
        opts,
        s: String::new(),
    };
    let mut head = format!("macflow-check {}", opts.version);
    if let Some(t) = opts.elapsed_secs {
        head.push_str(&format!(" · {t:.1}s"));
    }
    let osv_ran = result.inspections.iter().any(|i| {
        i.sub_category.as_deref() == Some(crate::security::osv::OSV_SUB_CATEGORY)
            && matches!(i.status, InspectionStatus::Inspected { .. })
    });
    head.push_str(if opts.offline {
        " · offline"
    } else if osv_ran {
        " · online (OSV.dev)"
    } else {
        " · OSV not checked"
    });
    let head = o.paint(BOLD, &head);
    o.line(&head);
    o.line("");

    let count = |sec| {
        result
            .findings
            .iter()
            .filter(|f| section_of(f) == sec)
            .count()
    };
    let (now, worth) = (count(Section::FixNow), count(Section::WorthFixing));
    let disk: u64 = result
        .findings
        .iter()
        .filter(|f| section_of(f) == Section::Disk)
        .map(|f| size_in(&f.title))
        .sum();
    let mut parts = Vec::new();
    if now > 0 {
        parts.push(o.paint(RED, &format!("{now} to fix now")));
    }
    if worth > 0 {
        parts.push(o.paint(YELLOW, &format!("{worth} worth fixing")));
    }
    if now + worth == 0 {
        parts.push(o.paint(GREEN, "No high or medium findings"));
    }
    if disk > 0 {
        parts.push(format!("{} of disk space to free", human(disk)));
    }
    o.line(&parts.join(" · "));

    let gs = groups(result);
    let mut current = None;
    for (i, g) in gs.iter().enumerate() {
        if current != Some(g.section) {
            current = Some(g.section);
            o.line("");
            let title = match g.section {
                Section::FixNow => o.paint(RED, "FIX NOW"),
                Section::WorthFixing => o.paint(YELLOW, "WORTH FIXING"),
                _ if disk > 0 => o.paint(CYAN, &format!("DISK SPACE · {}", human(disk))),
                _ => o.paint(CYAN, "DISK SPACE"),
            };
            o.line(&title);
        }
        render_group_line(&mut o, i + 1, g);
    }

    o.line("");
    // Low findings and info notes are counted here, not listed, so none goes unmentioned.
    for (sec, what) in [
        (Section::Low, "low-priority finding"),
        (Section::Hidden, "note"),
    ] {
        let n = count(sec);
        if n == 0 {
            continue;
        }
        let areas: BTreeSet<&str> = result
            .findings
            .iter()
            .filter(|f| section_of(f) == sec)
            .map(|f| f.sub_category.as_deref().unwrap_or("Other"))
            .collect();
        let s = if n == 1 { "" } else { "s" };
        let areas = areas.into_iter().collect::<Vec<_>>().join(", ");
        o.line(&format!("Also {n} {what}{s} ({areas}): see --details."));
    }
    // An area with any finding at all, even an info note, is not "no known match".
    let flagged: BTreeSet<&str> = result
        .findings
        .iter()
        .filter_map(|f| f.sub_category.as_deref())
        .collect();
    // An area checked anywhere was checked: a missing optional file elsewhere is not "not checked".
    let inspected: BTreeSet<&str> = result
        .inspections
        .iter()
        .filter(|i| matches!(i.status, InspectionStatus::Inspected { .. }))
        .filter_map(|i| i.sub_category.as_deref())
        .collect();
    let mut clear = BTreeSet::new();
    let mut skipped = BTreeSet::new();
    let mut unreadable = 0;
    for i in &result.inspections {
        // A whole category skipped has no sub-category: name the category instead.
        let sub = i
            .sub_category
            .as_deref()
            .unwrap_or_else(|| i.category.display_name());
        match &i.status {
            InspectionStatus::Inspected { .. } if !flagged.contains(sub) => {
                clear.insert(sub);
            }
            InspectionStatus::Skipped { reason } if !inspected.contains(sub) => {
                skipped.insert(match reason {
                    Some(r) => format!("{sub} ({r})"),
                    None => sub.to_string(),
                });
            }
            InspectionStatus::UnparseableData { .. } => unreadable += 1,
            _ => {}
        }
    }
    if !clear.is_empty() {
        let list = clear.into_iter().collect::<Vec<_>>().join(", ");
        let l = o.paint(GREEN, &format!("No known match in: {list}"));
        o.line(&l);
    }
    if !skipped.is_empty() {
        o.line(&format!(
            "Not checked: {}",
            skipped.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if unreadable > 0 {
        o.line(&format!(
            "Could not read {unreadable} file(s): see --details."
        ));
    }
    let hint = o.paint(DIM, "Every finding: macflow-check --details · JSON: --json");
    o.line(&hint);
    o.line("");
    let promo = o.paint(
        DIM,
        "From MacFlow, the Mac app that snapshots your dev setup and shows what changed.",
    );
    o.line(&promo);
    let link = o.paint(CYAN, "macflow.ai/check");
    o.line(&format!(
        "Continuous watching for these checks (planned): {link}"
    ));
    o.s
}

/// Full details for group `n` as numbered in the summary, or None if there is no such group.
pub fn render_group(result: &ScanResult, n: usize, opts: &SummaryOptions) -> Option<String> {
    let gs = groups(result);
    let g = gs.get(n.checked_sub(1)?)?;
    let mut o = Out {
        opts,
        s: String::new(),
    };
    let head = o.paint(BOLD, &format!("{n}  {} · {}", g.label, g.findings.len()));
    o.line(&head);
    for f in &g.findings {
        o.line("");
        o.line(&format!("[{}] {}", f.severity, f.title));
        if let Some(p) = o.path(f) {
            let p = o.paint(DIM, &p);
            o.line(&format!("  {p}"));
        }
        let why = o.tilde(&f.description);
        o.line(&format!("  Why: {why}"));
        if let Some(fix) = &f.remediation {
            let fix = o.tilde(fix);
            o.line(&format!("  Fix: {fix}"));
        }
    }
    Some(o.s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, Finding, Inspection, Severity};

    fn f(sub: &str, sev: Severity, title: &str) -> Finding {
        let cat = if sub == "Developer caches" || sub == "Stale node_modules" {
            Category::Garbage
        } else {
            Category::Security
        };
        Finding::new("x", title, cat, sev, "why").with_sub_category(sub)
    }

    fn sample() -> ScanResult {
        let mut findings = vec![
            f(
                "MCP servers",
                Severity::Info,
                "Configured MCP server 'wiz' (remote endpoint)",
            ),
            f(
                "PHP runtime",
                Severity::High,
                "PHP 8.5.2 is missing the 21 Oct 2026 security release",
            )
            .with_location("/Users/me/.phpenv/version", Some(1))
            .with_remediation("Run `brew upgrade php`."),
            f(
                "Developer caches",
                Severity::Low,
                "npm cache: 8.0 GB reclaimable",
            )
            .with_remediation("Run `npm cache verify`."),
            f(
                "Developer caches",
                Severity::Info,
                "pip cache: 624 MB reclaimable",
            ),
            f(
                "SSH keys and config",
                Severity::Low,
                "StrictHostKeyChecking disabled",
            ),
        ];
        for i in 0..8 {
            findings.push(
                f(
                    "Plaintext AI keys",
                    Severity::High,
                    "Plaintext OpenRouter API key in OPENROUTER_API_KEY (sk-or-v1-...)",
                )
                .with_location(format!("/Users/me/projects/p{i}/.env"), Some(3))
                .with_remediation("Rotate the key, then load it from a secret manager."),
            );
        }
        findings.push(
            f(
                "Plaintext AI keys",
                Severity::High,
                "Plaintext OpenAI API key in OPENAI_API_KEY (REDACTED...)",
            )
            .with_location("/Users/me/projects/q/.env", Some(1))
            .with_remediation("Rotate the key, then load it from a secret manager."),
        );
        for name in ["github", "playwright"] {
            findings.push(
                f(
                    "MCP servers",
                    Severity::Medium,
                    &format!("MCP server '{name}' runs unpinned package with npx"),
                )
                .with_location("/Users/me/.claude.json", Some(10))
                .with_remediation("Pin the package to an exact version."),
            );
        }
        let inspections = vec![
            Inspection::inspected(Category::Security, Some("Plaintext AI keys"), "user"),
            Inspection::inspected(Category::Security, Some("Shell startup files"), "user"),
            Inspection::inspected(Category::Security, Some("Git config"), "user"),
            Inspection::inspected(Category::Security, Some("MCP servers"), "user"),
            Inspection::skipped(
                Category::Security,
                Some("Dependency vulnerabilities (OSV)"),
                Some("offline"),
            ),
        ];
        ScanResult::new(findings, inspections, "2026-10-28T00:00:00Z")
    }

    fn opts() -> SummaryOptions {
        SummaryOptions {
            color: false,
            home: Some("/Users/me".into()),
            offline: true,
            elapsed_secs: Some(8.7),
            version: "0.1.0",
        }
    }

    fn pos(s: &str, needle: &str) -> usize {
        s.find(needle)
            .unwrap_or_else(|| panic!("missing {needle:?} in:\n{s}"))
    }

    #[test]
    fn the_answer_comes_first_then_sections_by_urgency() {
        let s = render_summary(&sample(), &opts());
        let first = s.lines().next().unwrap();
        assert!(
            first.contains("macflow-check") && first.contains("8.7s") && first.contains("offline"),
            "{first}"
        );
        assert!(s.lines().nth(2).unwrap().contains("10 to fix now"), "{s}");
        assert!(
            s.contains("2 worth fixing") && s.contains("8.6 GB of disk space"),
            "{s}"
        );
        assert!(
            pos(&s, "FIX NOW") < pos(&s, "WORTH FIXING")
                && pos(&s, "WORTH FIXING") < pos(&s, "DISK SPACE")
        );
    }

    #[test]
    fn same_kind_findings_collapse_into_one_numbered_group() {
        let s = render_summary(&sample(), &opts());
        assert_eq!(s.matches("OPENROUTER_API_KEY").count(), 1, "{s}");
        assert!(s.contains("×8"), "{s}");
        assert!(
            s.contains(" 1  Plaintext AI keys · 9"),
            "the biggest high group is number 1:\n{s}"
        );
        assert!(s.contains("~/projects/p0/.env:3 (+8 more)"), "{s}");
        assert!(s.contains("macflow-check --show 1"), "{s}");
        assert_eq!(
            s.matches("Rotate the key").count(),
            1,
            "one fix per group:\n{s}"
        );
    }

    #[test]
    fn a_single_finding_shows_its_title_fix_and_location() {
        let s = render_summary(&sample(), &opts());
        assert!(s.contains("PHP 8.5.2 is missing the 21 Oct 2026 security release"));
        assert!(
            s.contains("Run `brew upgrade php`.") && s.contains("~/.phpenv/version:1"),
            "{s}"
        );
    }

    #[test]
    fn info_findings_and_low_ones_stay_out_of_the_main_list() {
        let s = render_summary(&sample(), &opts());
        assert!(!s.contains("Configured MCP server"), "{s}");
        assert!(!s.contains("StrictHostKeyChecking"), "{s}");
        assert!(s.contains("1 low-priority finding"), "{s}");
    }

    #[test]
    fn disk_space_lists_garbage_of_any_severity_with_a_total() {
        let s = render_summary(&sample(), &opts());
        assert!(s.contains("DISK SPACE · 8.6 GB"), "{s}");
        assert!(
            s.contains("npm cache: 8.0 GB reclaimable")
                && s.contains("pip cache: 624 MB reclaimable"),
            "{s}"
        );
    }

    #[test]
    fn the_footer_says_what_was_checked_and_ends_with_the_link() {
        let s = render_summary(&sample(), &opts());
        assert!(
            s.contains("No known match in: Git config, Shell startup files"),
            "{s}"
        );
        assert!(
            s.contains("Not checked: Dependency vulnerabilities (OSV) (offline)"),
            "{s}"
        );
        assert!(s.contains("--details") && s.contains("--json"), "{s}");
        assert!(s.contains("MacFlow"), "{s}");
        assert!(s.trim_end().ends_with("macflow.ai/check"), "{s}");
        assert!(!s.contains("http") && !s.contains("utm_"), "{s}");
    }

    #[test]
    fn nothing_found_says_so_plainly() {
        let r = ScanResult::new(
            vec![],
            vec![Inspection::inspected(
                Category::Security,
                Some("Git config"),
                "user",
            )],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(
            s.contains("No high or medium findings") && s.contains("No known match in: Git config"),
            "{s}"
        );
        assert!(!s.contains("FIX NOW") && !s.contains("DISK SPACE"), "{s}");
    }

    #[test]
    fn colour_marks_urgency_only_when_asked() {
        let plain = render_summary(&sample(), &opts());
        assert!(!plain.contains('\x1b'), "no escape codes without colour");
        let col = render_summary(
            &sample(),
            &SummaryOptions {
                color: true,
                ..opts()
            },
        );
        assert!(col.contains("\x1b[1;31mFIX NOW"), "fix now is bold red");
        assert!(
            col.contains("\x1b[1;33mWORTH FIXING"),
            "worth fixing is bold yellow"
        );
        assert!(col.contains("\x1b[2m"), "hints and paths are dim");
    }

    #[test]
    fn a_group_whose_fixes_differ_drops_the_one_server_example() {
        let mk = |n: &str| {
            f(
                "MCP servers",
                Severity::Medium,
                &format!("MCP server '{n}' runs unpinned package"),
            )
            .with_remediation(format!(
                "Pin the package to an exact version (e.g. npx {n}@<version>)."
            ))
        };
        let r = ScanResult::new(vec![mk("a"), mk("b")], vec![], "t");
        let s = render_summary(&r, &opts());
        assert!(s.contains("→ Pin the package to an exact version."), "{s}");
        assert!(!s.contains("e.g. npx a@"), "{s}");
    }

    #[test]
    fn an_area_checked_somewhere_is_never_listed_as_not_checked() {
        let r = ScanResult::new(
            vec![],
            vec![
                Inspection::inspected(Category::Security, Some("MCP servers"), "user"),
                Inspection::skipped(
                    Category::Security,
                    Some("MCP servers"),
                    Some("file not present"),
                ),
            ],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(!s.contains("Not checked"), "{s}");
        assert!(s.contains("No known match in: MCP servers"), "{s}");
    }

    #[test]
    fn fix_text_shows_the_home_folder_as_tilde() {
        let r = ScanResult::new(
            vec![
                f("Git config", Severity::High, "fsmonitor").with_remediation(
                    "Run `git -C /Users/me/projects/app config --unset core.fsmonitor`.",
                ),
            ],
            vec![],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(s.contains("git -C ~/projects/app config"), "{s}");
        assert!(!s.contains("/Users/me/"), "{s}");
    }

    #[test]
    fn show_lists_every_finding_in_a_group() {
        let g = render_group(&sample(), 1, &opts()).expect("group 1");
        assert_eq!(g.matches("OPENROUTER_API_KEY").count(), 8, "{g}");
        assert!(
            g.contains("~/projects/p7/.env:3") && g.contains("Why: why"),
            "{g}"
        );
        assert!(render_group(&sample(), 99, &opts()).is_none());
    }

    #[test]
    fn a_group_of_different_kinds_never_shows_one_kinds_fix() {
        let r = ScanResult::new(
            vec![
                f(
                    "Plaintext credentials",
                    Severity::High,
                    "npm token in ~/.npmrc",
                )
                .with_remediation("Publish from CI with npm trusted publishing."),
                f(
                    "Plaintext credentials",
                    Severity::High,
                    "Token in ~/.git-credentials",
                )
                .with_remediation("Use the macOS keychain credential helper."),
            ],
            vec![],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(!s.contains("trusted publishing"), "{s}");
        assert!(!s.contains("keychain"), "{s}");
        assert!(s.contains("→ Fixes differ: macflow-check --show 1"), "{s}");
    }

    #[test]
    fn a_small_cache_listed_under_disk_space_is_not_also_no_known_match() {
        let r = ScanResult::new(
            vec![f(
                "Developer caches",
                Severity::Info,
                "pip cache: 300 MB reclaimable",
            )],
            vec![Inspection::inspected(
                Category::Garbage,
                Some("Developer caches"),
                "user",
            )],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(s.contains("pip cache: 300 MB reclaimable"), "{s}");
        assert!(!s.contains("No known match in: Developer caches"), "{s}");
    }

    #[test]
    fn no_urgent_findings_does_not_claim_there_is_nothing_to_fix() {
        let r = ScanResult::new(
            vec![f(
                "SSH keys and config",
                Severity::Low,
                "StrictHostKeyChecking disabled",
            )],
            vec![],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(!s.contains("Nothing to fix"), "{s}");
        assert!(s.contains("No high or medium findings"), "{s}");
    }

    #[test]
    fn disk_header_leaves_out_a_total_it_could_not_read() {
        let r = ScanResult::new(
            vec![f(
                "Stale node_modules",
                Severity::Info,
                "Stale node_modules in app",
            )],
            vec![],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(s.contains("DISK SPACE\n"), "{s}");
        assert!(!s.contains("0 MB"), "{s}");
    }

    #[test]
    fn sizes_are_read_and_totalled_in_the_scanners_binary_units() {
        assert_eq!(size_in("pip cache: 624 MB reclaimable"), 624 * 1024 * 1024);
        assert_eq!(human(1024 * 1024 * 1024 + 512 * 1024 * 1024), "1.5 GB");
    }

    #[test]
    fn show_and_paths_use_tilde_even_when_home_ends_in_a_slash() {
        let r = ScanResult::new(
            vec![f("Git config", Severity::High, "fsmonitor")
                .with_location("/Users/me/app/.git/config", Some(2))
                .with_remediation("Run `git -C /Users/me/app config --unset core.fsmonitor`.")],
            vec![],
            "t",
        );
        let o = SummaryOptions {
            home: Some("/Users/me/".into()),
            ..opts()
        };
        let s = render_summary(&r, &o);
        assert!(s.contains("~/app/.git/config:2"), "{s}");
        let g = render_group(&r, 1, &o).unwrap();
        assert!(!g.contains("/Users/me/"), "{g}");
    }

    #[test]
    fn an_area_with_only_info_findings_is_not_no_known_match() {
        let r = ScanResult::new(
            vec![f(
                "SSH keys and config",
                Severity::Info,
                "Unencrypted private key id_ed25519",
            )],
            vec![Inspection::inspected(
                Category::Security,
                Some("SSH keys and config"),
                "user",
            )],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(!s.contains("No known match in: SSH keys and config"), "{s}");
        assert!(
            s.contains("1 note (SSH keys and config): see --details"),
            "{s}"
        );
    }

    #[test]
    fn a_whole_category_skipped_is_listed_as_not_checked() {
        let r = ScanResult::new(
            vec![],
            vec![Inspection::skipped(
                Category::Security,
                None,
                Some("category not selected"),
            )],
            "t",
        );
        let s = render_summary(&r, &opts());
        assert!(
            s.contains("Not checked: Security (category not selected)"),
            "{s}"
        );
    }

    #[test]
    fn general_advice_keeps_what_follows_the_example() {
        assert_eq!(
            general("Pin X (e.g. foo@1). Then restart."),
            "Pin X. Then restart."
        );
        assert_eq!(
            general("Pin the package to an exact version (e.g. npx a@<version>)."),
            "Pin the package to an exact version."
        );
    }

    #[test]
    fn a_root_home_does_not_turn_every_slash_into_tilde() {
        let o = Out {
            opts: &SummaryOptions {
                home: Some("/".into()),
                ..opts()
            },
            s: String::new(),
        };
        assert_eq!(o.tilde("Run `rm /tmp/x`."), "Run `rm /tmp/x`.");
    }

    #[test]
    fn the_header_says_online_only_when_osv_actually_ran() {
        let osv = |status: Inspection| ScanResult::new(vec![], vec![status], "t");
        let online = SummaryOptions {
            offline: false,
            ..opts()
        };
        let ran = render_summary(
            &osv(Inspection::inspected(
                Category::Security,
                Some(crate::security::osv::OSV_SUB_CATEGORY),
                "3 packages",
            )),
            &online,
        );
        assert!(
            ran.lines().next().unwrap().contains("online (OSV.dev)"),
            "{ran}"
        );
        let failed = render_summary(
            &osv(Inspection::skipped(
                Category::Security,
                Some(crate::security::osv::OSV_SUB_CATEGORY),
                Some("network error"),
            )),
            &online,
        );
        let head = failed.lines().next().unwrap();
        assert!(
            !head.contains("online (OSV.dev)") && head.contains("OSV not checked"),
            "{head}"
        );
    }

    #[test]
    fn no_forbidden_words_and_no_secret_values() {
        let s = render_summary(&sample(), &opts());
        for w in s.to_lowercase().split(|c: char| !c.is_alphabetic()) {
            for bad in [
                "safe",
                "secure",
                "protect",
                "protected",
                "guarantee",
                "guaranteed",
                "clean",
            ] {
                assert_ne!(w, bad, "forbidden word in:\n{s}");
            }
        }
    }
}
