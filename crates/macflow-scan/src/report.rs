use std::collections::{HashMap, HashSet};

use crate::models::{Category, CategoryCoverage, Finding, InspectionStatus, ScanResult, Severity};

/// Renders a terminal-friendly truthful report adhering to `macflow-voice`.
/// Unchecked/skipped checks report `[not checked]`. Never claims "safe". Every finding is rendered.
pub fn render_report(result: &ScanResult) -> String {
    let mut out = String::new();
    out.push_str("macflow-check scan report\n=========================\n\n");

    for category in Category::all() {
        out.push_str(&format!("[{}]\n", category.display_name()));

        let inspections = result.inspections_for_category(*category);
        let cat_findings = result.findings_for_category(*category);

        if inspections.is_empty() {
            let note = if cat_findings.is_empty() {
                ""
            } else {
                " (module not inspected)"
            };
            out.push_str(&format!("  [not checked]{note}\n"));
            if !cat_findings.is_empty() {
                out.push_str("  - Other findings:\n");
                for finding in &cat_findings {
                    render_finding_item(&mut out, finding, "    ");
                }
            }
            out.push('\n');
            continue;
        }

        let mut inspected_counts: HashMap<Option<&str>, usize> = HashMap::new();
        let mut sub_inspected_scopes: HashMap<Option<&str>, Vec<&str>> = HashMap::new();
        for insp in &inspections {
            if let InspectionStatus::Inspected { inspected_scope } = &insp.status {
                *inspected_counts
                    .entry(insp.sub_category.as_deref())
                    .or_insert(0) += 1;
                sub_inspected_scopes
                    .entry(insp.sub_category.as_deref())
                    .or_default()
                    .push(inspected_scope.as_str());
            }
        }

        let mut unplaced_sub_findings_count: HashMap<Option<&str>, usize> = HashMap::new();
        for f in &cat_findings {
            let sub = f.sub_category.as_deref();
            if let Some(scopes) = sub_inspected_scopes.get(&sub) {
                if scopes.len() > 1 {
                    let matches_any = scopes.iter().any(|scope| finding_matches_scope(f, scope));
                    if !matches_any {
                        *unplaced_sub_findings_count.entry(sub).or_insert(0) += 1;
                    }
                }
            }
        }

        let mut rendered_indices = HashSet::new();
        let mut reported_unplaced_subcategories = HashSet::new();
        for insp in &inspections {
            let prefix = match &insp.sub_category {
                Some(sub) => format!("  - {sub}: "),
                None => "  ".to_string(),
            };

            match &insp.status {
                InspectionStatus::Skipped { reason } => {
                    let s = reason
                        .as_deref()
                        .map(|r| format!(": {r}"))
                        .unwrap_or_default();
                    out.push_str(&format!("{prefix}[not checked] (module skipped{s})\n"));
                }
                InspectionStatus::UnparseableData { path, error } => {
                    let l = path
                        .as_deref()
                        .map(|p| format!(" in {p}"))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "{prefix}[not checked] (unparseable data{l}: {error})\n"
                    ));
                }
                InspectionStatus::Inspected { inspected_scope } => {
                    let sibling_inspected_count = inspected_counts
                        .get(&insp.sub_category.as_deref())
                        .copied()
                        .unwrap_or(0);

                    let matches: Vec<(usize, &Finding)> = cat_findings
                        .iter()
                        .enumerate()
                        .filter(|(idx, f)| {
                            if rendered_indices.contains(idx) {
                                return false;
                            }
                            if f.sub_category.as_deref() != insp.sub_category.as_deref() {
                                return false;
                            }
                            if sibling_inspected_count > 1 {
                                finding_matches_scope(f, inspected_scope)
                            } else {
                                true
                            }
                        })
                        .map(|(idx, f)| (idx, *f))
                        .collect();

                    if matches.is_empty() {
                        let unplaced = unplaced_sub_findings_count
                            .get(&insp.sub_category.as_deref())
                            .copied()
                            .unwrap_or(0);
                        if unplaced > 0 {
                            if reported_unplaced_subcategories.insert(insp.sub_category.as_deref())
                            {
                                out.push_str(&format!(
                                    "{prefix}{unplaced} item(s), scope unknown\n"
                                ));
                            }
                        } else {
                            out.push_str(&format!("{prefix}no known match ({inspected_scope})\n"));
                        }
                    } else {
                        for (idx, _) in &matches {
                            rendered_indices.insert(*idx);
                        }
                        let n = matches.len();
                        let h = if n == 1 {
                            "Found 1 item:\n".to_string()
                        } else {
                            format!("Found {n} items:\n")
                        };
                        out.push_str(&format!("{prefix}{h}"));
                        let indent = if insp.sub_category.is_some() {
                            "    "
                        } else {
                            "  "
                        };
                        for (_, finding) in matches {
                            render_finding_item(&mut out, finding, indent);
                        }
                    }
                }
            }
        }

        let unrendered: Vec<&Finding> = cat_findings
            .iter()
            .enumerate()
            .filter(|(idx, _)| !rendered_indices.contains(idx))
            .map(|(_, f)| *f)
            .collect();
        if !unrendered.is_empty() {
            out.push_str("  - Other findings:\n");
            for finding in unrendered {
                render_finding_item(&mut out, finding, "    ");
            }
        }
        out.push('\n');
    }

    let cov = [
        CategoryCoverage::Checked,
        CategoryCoverage::PartiallyChecked,
        CategoryCoverage::NotChecked,
    ]
    .map(|v| {
        let n: Vec<_> = Category::all()
            .iter()
            .filter(|c| result.category_coverage(**c) == v)
            .map(|c| c.display_name())
            .collect();
        if n.is_empty() {
            "none".to_string()
        } else {
            n.join(", ")
        }
    });
    out.push_str(&format!(
        "Summary\n-------\nTotal findings: {}\n  Critical: {}\n  High:     {}\n  Medium:   {}\n  Low:      {}\n  Info:     {}\n\nChecked categories: {}\nPartially checked: {}\nNot checked: {}\n\nContinuous watching (planned): macflow.ai/check\n",
        result.findings.len(),
        result.count_by_severity(Severity::Critical), result.count_by_severity(Severity::High),
        result.count_by_severity(Severity::Medium), result.count_by_severity(Severity::Low),
        result.count_by_severity(Severity::Info), cov[0], cov[1], cov[2],
    ));

    out
}

fn render_finding_item(out: &mut String, finding: &Finding, indent: &str) {
    out.push_str(&format!(
        "{indent}- [{}] {}\n",
        finding.severity, finding.title
    ));
    if let Some(p) = &finding.file_path {
        let l = finding
            .line_number
            .map(|n| format!(":{n}"))
            .unwrap_or_default();
        out.push_str(&format!("{indent}  Location: {p}{l}\n"));
    }
    out.push_str(&format!("{indent}  Why: {}\n", finding.description));
    if let Some(fix) = &finding.remediation {
        out.push_str(&format!("{indent}  Fix: {fix}\n"));
    }
}

fn is_user_library_path(p_norm: &str) -> bool {
    let p_lower = p_norm.to_lowercase();
    if p_lower.starts_with("~/library/")
        || p_lower == "~/library"
        || p_lower.starts_with("$home/library/")
        || p_lower == "$home/library"
        || p_lower.starts_with("/library/")
        || p_lower == "/library"
        || p_lower.starts_with("library/")
        || p_lower == "library"
    {
        return true;
    }
    let parts: Vec<&str> = p_norm.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 3
        && (parts[0].eq_ignore_ascii_case("Users") || parts[0].eq_ignore_ascii_case("home"))
        && parts[2].eq_ignore_ascii_case("Library")
    {
        return true;
    }
    false
}

fn is_user_dev_root(p_norm: &str) -> bool {
    let parts: Vec<&str> = p_norm.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return false;
    }

    let dev_roots = ["code", "dev", "src", "developer", "github"];

    // ~/code/... or $HOME/code/...
    if p_norm.starts_with('~') || p_norm.to_lowercase().starts_with("$home") {
        let first = parts[0];
        let cand = if first == "~" || first.eq_ignore_ascii_case("$home") {
            parts.get(1).copied()
        } else if let Some(stripped) = first.strip_prefix('~') {
            if !stripped.is_empty() {
                Some(stripped)
            } else {
                parts.get(1).copied()
            }
        } else {
            None
        };
        if let Some(c) = cand {
            if dev_roots.iter().any(|r| c.eq_ignore_ascii_case(r)) {
                return true;
            }
        }
    }

    // /Users/<username>/<root>/... or /home/<username>/<root>/...
    if parts.len() >= 3
        && (parts[0].eq_ignore_ascii_case("Users") || parts[0].eq_ignore_ascii_case("home"))
    {
        let cand = parts[2];
        if dev_roots.iter().any(|r| cand.eq_ignore_ascii_case(r)) {
            return true;
        }
    }

    false
}

fn is_project_path(p: &str) -> bool {
    let p_norm = p.replace('\\', "/");
    if is_user_library_path(&p_norm) {
        return false;
    }

    let p_lower = p_norm.to_lowercase();
    if p_lower == "proj" || p_lower == "project" || p_lower == "local" || p_lower == "workspace" {
        return true;
    }
    if p_lower.starts_with("proj/")
        || p_lower.starts_with("project/")
        || p_lower.starts_with("local/")
        || p_lower.starts_with("./")
        || p_lower.starts_with("../")
        || p_lower.starts_with(".claude/")
        || p_lower.starts_with("./.claude/")
        || p_lower.starts_with(".vscode/")
        || p_lower.starts_with("./.vscode/")
        || p_lower.starts_with(".git/")
        || p_lower.starts_with("./.git/")
    {
        return true;
    }
    if p_lower.contains("/projects/")
        || p_lower.contains("/project/")
        || p_lower.contains("/workspace/")
        || p_lower.contains("/workspaces/")
        || p_lower.contains("/repos/")
        || p_lower.contains("/repo/")
        || p_lower.contains("/proj/")
        || p_lower.contains("/wt/")
    {
        return true;
    }

    if is_user_dev_root(&p_norm) {
        return true;
    }

    if p_lower.contains("/.claude/") || p_lower.contains("/.vscode/") {
        let parts: Vec<&str> = p_norm.split('/').filter(|s| !s.is_empty()).collect();
        let is_direct_home_config = p_lower.starts_with("~/.claude/")
            || p_lower.starts_with("~/.vscode/")
            || p_lower.starts_with("$home/.claude/")
            || p_lower.starts_with("$home/.vscode/")
            || (parts
                .first()
                .map(|s| s.eq_ignore_ascii_case("Users") || s.eq_ignore_ascii_case("home"))
                .unwrap_or(false)
                && parts.len() >= 3
                && (parts[2].eq_ignore_ascii_case(".claude")
                    || parts[2].eq_ignore_ascii_case(".vscode")));
        if !is_direct_home_config {
            return true;
        }
    }
    if !p_norm.starts_with('/')
        && !p_norm.starts_with('~')
        && !p_norm.starts_with("$HOME")
        && !p_lower.starts_with("user")
        && !p_lower.starts_with("global")
    {
        return true;
    }
    false
}

fn is_user_path(p: &str) -> bool {
    let p_norm = p.replace('\\', "/");
    let p_lower = p_norm.to_lowercase();
    if p_lower == "user" || p_lower == "global" || p_lower == "home" {
        return true;
    }
    if p_lower.starts_with("user/") || p_lower.starts_with("global/") {
        return true;
    }
    if is_user_library_path(&p_norm) {
        return true;
    }
    if is_project_path(p) {
        return false;
    }
    p_norm.starts_with('~')
        || p_norm.starts_with("$HOME")
        || p_norm.starts_with("/Users/")
        || p_norm.starts_with("/home/")
        || p_norm.starts_with("/Library/")
        || p_norm.starts_with("/etc/")
}

fn path_components_match(p: &str, s: &str) -> bool {
    let p_norm = p.replace('\\', "/");
    let s_norm = s.replace('\\', "/");
    let p_clean = p_norm.trim_matches('/');
    let s_clean = s_norm.trim_matches('/');

    if s_clean.is_empty() || p_clean.is_empty() {
        return false;
    }

    if p_clean.eq_ignore_ascii_case(s_clean) {
        return true;
    }

    let p_lower = p_clean.to_lowercase();
    let s_lower = s_clean.to_lowercase();

    let s_suffix = format!("/{s_lower}");
    if p_lower.ends_with(&s_suffix) {
        return true;
    }

    let p_suffix = format!("/{p_lower}");
    if s_lower.ends_with(&p_suffix) {
        return true;
    }

    false
}

fn finding_matches_scope(finding: &Finding, scope: &str) -> bool {
    let s = scope.trim();
    if s.is_empty() {
        return false;
    }

    let s_lower = s.to_lowercase();
    let (s_is_proj_prefix, s_rel_opt) = if s_lower.starts_with("proj:") {
        (true, Some(s[5..].trim()))
    } else if s_lower.starts_with("project:") {
        (true, Some(s[8..].trim()))
    } else {
        (false, None)
    };

    if let Some(ref f_scope) = finding.scope {
        let fs = f_scope.trim();
        if fs.eq_ignore_ascii_case(s) {
            return true;
        }

        let fs_lower = fs.to_lowercase();
        let fs_is_proj = fs_lower == "proj"
            || fs_lower == "project"
            || fs_lower.starts_with("proj:")
            || fs_lower.starts_with("project:");
        let s_is_proj = s_lower == "proj" || s_lower == "project" || s_is_proj_prefix;

        if fs_is_proj && s_is_proj {
            if let Some(rel) = s_rel_opt {
                if !rel.is_empty() {
                    if let Some(ref path) = finding.file_path {
                        if path_components_match(path, rel) {
                            return true;
                        }
                    }
                    let fs_rel_opt = if fs_lower.starts_with("proj:") {
                        Some(fs[5..].trim())
                    } else if fs_lower.starts_with("project:") {
                        Some(fs[8..].trim())
                    } else {
                        None
                    };
                    if let Some(fs_rel) = fs_rel_opt {
                        if path_components_match(fs_rel, rel) {
                            return true;
                        }
                    }
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    let Some(ref path) = finding.file_path else {
        return false;
    };
    let p = path.trim();
    if p.is_empty() {
        return false;
    }

    if p.eq_ignore_ascii_case(s) {
        return true;
    }

    if s_lower == "user" || s_lower == "global" || s_lower == "home" {
        return is_user_path(p);
    }

    if s_lower == "proj" || s_lower == "project" || s_lower == "local" || s_lower == "workspace" {
        return is_project_path(p);
    }

    if s_is_proj_prefix {
        if let Some(rel) = s_rel_opt {
            if is_project_path(p) && (rel.is_empty() || path_components_match(p, rel)) {
                return true;
            }
        }
    }

    path_components_match(p, s)
}

/// Serializes the `ScanResult` into formatted JSON.
pub fn render_json(result: &ScanResult) -> Result<String, serde_json::Error> {
    let mut val = serde_json::to_value(result)?;
    if let Some(obj) = val.as_object_mut() {
        obj.insert(
            "summary".to_string(),
            serde_json::json!({
                "total": result.findings.len(),
                "critical": result.count_by_severity(Severity::Critical),
                "high": result.count_by_severity(Severity::High),
                "medium": result.count_by_severity(Severity::Medium),
                "low": result.count_by_severity(Severity::Low),
                "info": result.count_by_severity(Severity::Info),
            }),
        );
    }
    serde_json::to_string_pretty(&val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Finding, Inspection};

    fn assert_no_forbidden_words(text: &str) {
        let lower = text.to_lowercase();
        for word in lower.split(|c: char| !c.is_alphabetic()) {
            for f in [
                "safe",
                "secure",
                "protect",
                "protected",
                "guarantee",
                "guaranteed",
                "clean",
            ] {
                assert_ne!(word, f, "Forbidden word '{f}' in:\n{text}");
            }
        }
    }

    #[test]
    fn test_empty_scan_result_honest_reporting() {
        let r = render_report(&ScanResult::empty("2026-10-20T00:00:00Z"));
        assert!(
            r.contains("[AI agent setup]\n  [not checked]")
                && r.contains("[Security]\n  [not checked]")
                && r.contains("[Garbage]\n  [not checked]")
        );
        assert!(!r.contains("no known match") && !r.contains("you're safe"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_report_with_findings_and_severity_counts() {
        let f1 = Finding::new("ai-1", "H", Category::AgentAudit, Severity::Critical, "D")
            .with_sub_category("Claude Code hooks")
            .with_location("~/.claude/settings.json", Some(14))
            .with_remediation("Remove hook");
        let f2 = Finding::new("sec-1", "Vuln", Category::Security, Severity::High, "D")
            .with_location("package-lock.json", None)
            .with_remediation("Upgrade lodash");
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "1 file"),
            Inspection::inspected(Category::Security, None, "inspected package-lock.json"),
            Inspection::skipped(Category::Garbage, None, None),
        ];
        let r = render_report(&ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("Total findings: 2") && r.contains("Critical: 1\n  High:     1"));
        assert!(
            r.contains("Location: ~/.claude/settings.json:14")
                && r.contains("Why: D")
                && r.contains("Fix: Remove hook")
        );
        assert!(
            r.contains("[Garbage]\n  [not checked] (module skipped)")
                && r.contains("Continuous watching (planned): macflow.ai/check")
        );
        assert!(!r.contains("Continuous watching: macflow.ai/check\n"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_findings_not_dropped_input_a_unattributed_finding() {
        let f = Finding::new("ai-u1", "Risk", Category::AgentAudit, Severity::High, "D");
        let insp = Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "1 file");
        let r = render_report(&ScanResult::new(
            vec![f],
            vec![insp],
            "2026-10-20T00:00:00Z",
        ));
        assert!(r.contains("Claude Code hooks: no known match (1 file)"));
        assert!(
            r.contains("Other findings:\n    - [HIGH] Risk")
                && r.contains("Total findings: 1\n  Critical: 0\n  High:     1")
        );
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_findings_not_dropped_input_b_and_honest_inspections() {
        let f1 = Finding::new("ai-u1", "Task", Category::AgentAudit, Severity::Medium, "D")
            .with_sub_category("VS Code tasks");
        let f2 = Finding::new("sec-s1", "Key", Category::Security, Severity::Low, "D")
            .with_sub_category("API Keys");
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "s.json"),
            Inspection::unparseable(
                Category::AgentAudit,
                Some("VS Code tasks"),
                Some("t.json"),
                "err",
            ),
            Inspection::skipped(Category::Security, Some("API Keys"), Some("disabled")),
        ];
        let r = render_report(&ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("- Claude Code hooks: no known match (s.json)"));
        assert!(r.contains("- VS Code tasks: [not checked] (unparseable data in t.json: err)"));
        assert!(r.contains("- API Keys: [not checked] (module skipped: disabled)"));
        assert!(
            r.contains("Other findings:")
                && r.contains("- [MEDIUM] Task")
                && r.contains("- [LOW] Key")
        );
        assert!(r.contains("Total findings: 2") && r.contains("[Garbage]\n  [not checked]"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_partially_checked_summary_reporting() {
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("hooks"), "1 file"),
            Inspection::unparseable(
                Category::AgentAudit,
                Some("tasks"),
                Some("t.json"),
                "syntax error",
            ),
        ];
        let r = render_report(&ScanResult::new(vec![], insp, "2026-10-20T00:00:00Z"));
        assert!(
            r.contains("Checked categories: none")
                && r.contains("Partially checked: AI agent setup")
                && r.contains("Not checked: Security, Garbage")
        );
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_json_rendering() {
        let f = Finding::new("f-1", "Test", Category::AgentAudit, Severity::Medium, "D");
        let insp = Inspection::inspected(Category::AgentAudit, None, "test");
        let result = ScanResult::new(vec![f], vec![insp], "2026-10-20T00:00:00Z");
        let json = render_json(&result).unwrap();
        assert!(json.contains("\"id\": \"f-1\"") && json.contains("\"category\": \"agent_audit\""));
        assert!(
            json.contains("\"status\": \"inspected\"")
                && json.contains("\"inspected_scope\": \"test\"")
        );
    }

    #[test]
    fn test_two_findings_sharing_id_both_rendered() {
        let f1 = Finding::new(
            "mcp-unpinned",
            "MCP 1",
            Category::AgentAudit,
            Severity::High,
            "D",
        )
        .with_sub_category("MCP servers")
        .with_location("~/.claude.json", Some(10));
        let f2 = Finding::new(
            "mcp-unpinned",
            "MCP 2",
            Category::AgentAudit,
            Severity::Medium,
            "D",
        );
        let insp = vec![Inspection::inspected(
            Category::AgentAudit,
            Some("MCP servers"),
            "~/.claude.json",
        )];
        let r = render_report(&ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("MCP 1") && r.contains("MCP 2") && r.contains("Total findings: 2"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_multiple_inspections_sharing_sub_category_findings_rendered_once() {
        let f1 = Finding::new(
            "hook-c",
            "Hook",
            Category::AgentAudit,
            Severity::Critical,
            "D",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("~/.claude/settings.json", Some(12));
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];
        let r = render_report(&ScanResult::new(vec![f1], insp, "2026-10-20T00:00:00Z"));
        assert_eq!(r.matches("Hook").count(), 1);
        assert!(r.matches("Found 1 item").count() == 1 && r.contains("Total findings: 1"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_multiple_inspections_both_scopes_have_findings_no_false_no_known_match() {
        let f1 = Finding::new(
            "hook-u",
            "User Hook",
            Category::AgentAudit,
            Severity::High,
            "User hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("user", Some(10));
        let f2 = Finding::new(
            "hook-p",
            "Project Hook",
            Category::AgentAudit,
            Severity::Medium,
            "Project hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("proj", Some(20));
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];
        let r = render_report(&ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("User Hook"));
        assert!(r.contains("Project Hook"));
        assert!(!r.contains("no known match"));
        assert_eq!(r.matches("Found 1 item").count(), 2);
        assert!(r.contains("Total findings: 2"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_multiple_inspections_finding_in_proj_only_reports_user_no_known_match() {
        let f = Finding::new(
            "hook-p",
            "Project Hook",
            Category::AgentAudit,
            Severity::High,
            "Project hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("proj/settings.json", Some(5));
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];
        let r = render_report(&ScanResult::new(vec![f], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("no known match (user)"));
        assert!(!r.contains("no known match (proj)"));
        assert!(r.contains("Project Hook"));
        assert_eq!(r.matches("Found 1 item").count(), 1);
        assert!(r.contains("Total findings: 1"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_multiple_inspections_macos_user_path_in_proj_scope_not_claimed_by_user() {
        let f = Finding::new(
            "hook-p",
            "Project Hook",
            Category::AgentAudit,
            Severity::High,
            "Project hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("/Users/alice/projects/repo/.claude/settings.json", Some(10));
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];
        let r = render_report(&ScanResult::new(vec![f], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("no known match (user)"));
        assert!(!r.contains("no known match (proj)"));
        assert!(r.contains("Project Hook"));
        assert_eq!(r.matches("Found 1 item").count(), 1);
        assert!(r.contains("Total findings: 1"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_multiple_inspections_macos_user_and_proj_paths_both_attributed_correctly() {
        let f1 = Finding::new(
            "hook-u",
            "User Hook",
            Category::AgentAudit,
            Severity::High,
            "User hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("/Users/alice/.claude/settings.json", Some(12));
        let f2 = Finding::new(
            "hook-p",
            "Project Hook",
            Category::AgentAudit,
            Severity::Medium,
            "Project hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("/Users/alice/projects/repo/.claude/settings.json", Some(20));
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];
        let r = render_report(&ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("User Hook"));
        assert!(r.contains("Project Hook"));
        assert!(!r.contains("no known match"));
        assert_eq!(r.matches("Found 1 item").count(), 2);
        assert!(r.contains("Total findings: 2"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_scope_attribution_standard_code_root() {
        let f = Finding::new(
            "hook-p",
            "Project Hook",
            Category::AgentAudit,
            Severity::High,
            "Project hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("/Users/alice/code/app/.claude/settings.json", Some(10));
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];
        let r = render_report(&ScanResult::new(vec![f], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("no known match (user)"));
        assert!(!r.contains("no known match (proj)"));
        assert!(r.contains("Project Hook"));
        assert_eq!(r.matches("Found 1 item").count(), 1);
        assert!(r.contains("Total findings: 1"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_sub_category_unplaced_findings_render_scope_unknown() {
        let f = Finding::new(
            "hook-unplaced",
            "Hook Without Scope",
            Category::AgentAudit,
            Severity::Critical,
            "Hook finding lacking scope and path",
        )
        .with_sub_category("Claude Code hooks");
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];
        let r = render_report(&ScanResult::new(vec![f], insp, "2026-10-20T00:00:00Z"));
        assert!(!r.contains("no known match"));
        assert!(r.contains("Claude Code hooks: 1 item(s), scope unknown"));
        assert!(r.contains("Other findings:"));
        assert!(r.contains("Hook Without Scope"));
        assert!(r.contains("Total findings: 1"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_custom_scope_matching_and_boundary_guards() {
        let f1 = Finding::new(
            "custom-1",
            "Config Hook",
            Category::AgentAudit,
            Severity::High,
            "Config hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("/var/app/config/hooks.json", Some(1));
        let f2 = Finding::new(
            "custom-2",
            "Old Hook",
            Category::AgentAudit,
            Severity::Medium,
            "Old hook found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("/var/app/config/old-hooks.json", Some(2));
        let f3 = Finding::new(
            "custom-3",
            "App Script",
            Category::AgentAudit,
            Severity::Low,
            "App script found",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("my_app.js", Some(3));

        let insp = vec![
            Inspection::inspected(
                Category::AgentAudit,
                Some("Claude Code hooks"),
                "hooks.json",
            ),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "app.js"),
        ];

        let r = render_report(&ScanResult::new(
            vec![f1, f2, f3],
            insp,
            "2026-10-20T00:00:00Z",
        ));

        assert!(r.contains("Config Hook"));
        assert!(!r.contains("no known match (hooks.json)"));
        assert!(r.contains("2 item(s), scope unknown"));
        assert!(r.contains("Other findings:"));
        assert!(r.contains("Old Hook"));
        assert!(r.contains("App Script"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_explicit_finding_scope_attribution() {
        let f = Finding::new(
            "hook-explicit",
            "Explicit Proj Hook",
            Category::AgentAudit,
            Severity::Critical,
            "Hook with explicit project scope override",
        )
        .with_sub_category("Claude Code hooks")
        .with_scope("proj")
        .with_location("/Users/alice/.claude/settings.json", Some(5));

        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];

        let r = render_report(&ScanResult::new(vec![f], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("no known match (user)"));
        assert!(!r.contains("no known match (proj)"));
        assert!(r.contains("Explicit Proj Hook"));
        assert_eq!(r.matches("Found 1 item").count(), 1);
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_user_library_paths_attributed_to_user_scope() {
        let f1 = Finding::new(
            "vscode-user-tasks",
            "VS Code User Tasks",
            Category::AgentAudit,
            Severity::High,
            "User-level tasks configuration",
        )
        .with_sub_category("Claude Code hooks")
        .with_location(
            "/Users/alice/Library/Application Support/Code/User/tasks.json",
            Some(1),
        );

        let f2 = Finding::new(
            "developer-cache-test",
            "Developer Test Finding",
            Category::AgentAudit,
            Severity::Medium,
            "Developer directory configuration",
        )
        .with_sub_category("Claude Code hooks")
        .with_location("/Users/alice/Library/Developer/test.json", Some(2));

        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];

        let r = render_report(&ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z"));

        assert!(
            !r.contains("no known match (user)"),
            "Report should not contain 'no known match (user)':\n{r}"
        );
        assert!(
            r.contains("no known match (proj)"),
            "Proj scope should have no known match:\n{r}"
        );
        assert!(
            r.contains("Found 2 items:"),
            "Should find 2 items in user scope:\n{r}"
        );
        assert!(r.contains("VS Code User Tasks"));
        assert!(r.contains("Developer Test Finding"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_sub_category_unplaced_findings_rendered_once() {
        let f1 = Finding::new(
            "unplaced-1",
            "Unplaced 1",
            Category::AgentAudit,
            Severity::Medium,
            "Finding without location or scope",
        )
        .with_sub_category("Claude Code hooks");

        let f2 = Finding::new(
            "unplaced-2",
            "Unplaced 2",
            Category::AgentAudit,
            Severity::Low,
            "Another unplaced finding",
        )
        .with_sub_category("Claude Code hooks");

        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "proj"),
        ];

        let r = render_report(&ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z"));

        assert_eq!(
            r.matches("2 item(s), scope unknown").count(),
            1,
            "Expected '2 item(s), scope unknown' to appear exactly once:\n{r}"
        );
        assert!(!r.contains("no known match"));
        assert_no_forbidden_words(&r);
    }

    #[test]
    fn test_proj_relative_path_scope_matching() {
        let f = Finding::new(
            "hook-proj-rel",
            "Claude Settings Hook",
            Category::AgentAudit,
            Severity::High,
            "Dangerous hook detected in project settings",
        )
        .with_sub_category("Claude Code hooks")
        .with_location(
            "/Users/alice/projects/my-app/.claude/settings.json",
            Some(15),
        );

        let insp = vec![
            Inspection::inspected(Category::AgentAudit, Some("Claude Code hooks"), "user"),
            Inspection::inspected(
                Category::AgentAudit,
                Some("Claude Code hooks"),
                "proj:.claude/settings.json",
            ),
        ];

        let r = render_report(&ScanResult::new(vec![f], insp, "2026-10-20T00:00:00Z"));
        assert!(r.contains("no known match (user)"));
        assert!(!r.contains("no known match (proj:.claude/settings.json)"));
        assert!(!r.contains("scope unknown"));
        assert!(r.contains("Claude Settings Hook"));
        assert_eq!(r.matches("Found 1 item").count(), 1);
        assert_no_forbidden_words(&r);
    }
}
