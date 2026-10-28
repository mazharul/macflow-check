use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const PHP_SUB_CATEGORY: &str = "PHP runtime";

/// The 21 Oct 2026 security releases, confirmed on php.net's release feed.
/// Branches older than the first entry no longer receive security fixes.
const PATCHED: &[(u32, u32, u32)] = &[(8, 2, 35), (8, 3, 36), (8, 4, 27), (8, 5, 12)];
const RELEASE_DATE: &str = "21 Oct 2026";
const SOURCE: &str = "https://www.php.net/ChangeLog-8.php";

#[derive(Clone, Copy)]
enum Source {
    Homebrew,
    Asdf,
    Mise,
    Phpenv,
    Mamp,
}

struct Install {
    version: (u32, u32, u32),
    path: PathBuf,
    source: Source,
    /// Homebrew formula name (`php`, `php@8.3`), used in the fix command.
    formula: Option<String>,
}

/// Parses `8.4.27`, `8.4.27_1` (Homebrew revision) or `php8.4.27` (MAMP).
fn parse_version(name: &str) -> Option<(u32, u32, u32)> {
    let v = name.strip_prefix("php").unwrap_or(name);
    let v = v.split('_').next()?;
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn subdirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .filter_map(|p| Some((p.file_name()?.to_string_lossy().into_owned(), p)))
        .collect();
    out.sort();
    out
}

fn is_php_formula(name: &str) -> bool {
    name == "php"
        || name.strip_prefix("php@").is_some_and(|v| {
            v.split('.')
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
}

fn find_installs(system_root: &Path, home: Option<&Path>) -> Vec<Install> {
    let mut found = Vec::new();
    for cellar in ["opt/homebrew/Cellar", "usr/local/Cellar"] {
        for (formula, fdir) in subdirs(&system_root.join(cellar)) {
            if !is_php_formula(&formula) {
                continue;
            }
            for (name, path) in subdirs(&fdir) {
                if let Some(version) = parse_version(&name) {
                    found.push(Install {
                        version,
                        path,
                        source: Source::Homebrew,
                        formula: Some(formula.clone()),
                    });
                }
            }
        }
    }
    for (name, path) in subdirs(&system_root.join("Applications/MAMP/bin/php")) {
        if let Some(version) = parse_version(&name) {
            found.push(Install {
                version,
                path,
                source: Source::Mamp,
                formula: None,
            });
        }
    }
    if let Some(home) = home {
        for (rel, source) in [
            (".asdf/installs/php", Source::Asdf),
            (".local/share/mise/installs/php", Source::Mise),
            (".phpenv/versions", Source::Phpenv),
        ] {
            for (name, path) in subdirs(&home.join(rel)) {
                if let Some(version) = parse_version(&name) {
                    found.push(Install {
                        version,
                        path,
                        source,
                        formula: None,
                    });
                }
            }
        }
    }
    found
}

fn fix_command(inst: &Install) -> String {
    let (ma, mi, _) = inst.version;
    match inst.source {
        Source::Homebrew => format!(
            "Run `brew upgrade {}`.",
            inst.formula.as_deref().unwrap_or("php")
        ),
        Source::Asdf => format!("Run `asdf install php latest:{ma}.{mi}` and switch to it."),
        Source::Mise => format!("Run `mise install php@{ma}.{mi}` and switch to it."),
        Source::Phpenv => {
            format!("Install the latest {ma}.{mi} release with `phpenv install` and switch to it.")
        }
        Source::Mamp => {
            "Update MAMP to a release that bundles a patched PHP, or stop using this PHP version."
                .to_string()
        }
    }
}

fn inspect(inst: &Install) -> Option<Finding> {
    let (ma, mi, pa) = inst.version;
    let ver = format!("{ma}.{mi}.{pa}");
    let oldest = PATCHED[0];
    let (title, desc, rem) = if (ma, mi) < (oldest.0, oldest.1) {
        (
            format!("PHP {ver} no longer receives security fixes"),
            format!(
                "PHP {ma}.{mi} is past end of life, so known vulnerabilities in it will not be fixed. \
                 This matters when PHP serves requests (php -S, PHP-FPM, Valet or Herd). Source: {SOURCE}"
            ),
            format!("Move to a supported branch (8.2 or newer). {}", fix_command(inst)),
        )
    } else {
        let &(_, _, min) = PATCHED.iter().find(|&&(a, b, _)| (a, b) == (ma, mi))?;
        if pa >= min {
            return None;
        }
        (
            format!("PHP {ver} is missing the {RELEASE_DATE} security release"),
            format!(
                "PHP {ver} predates {ma}.{mi}.{min}, which fixes remote code execution bugs, including memory \
                 corruption when PHP runs out of memory. They are exploitable when PHP serves requests \
                 (php -S, PHP-FPM, Valet or Herd). Source: {SOURCE}"
            ),
            fix_command(inst),
        )
    };
    let path = inst.path.to_string_lossy();
    Some(
        Finding::new(
            "php-runtime-outdated",
            title,
            Category::Security,
            Severity::High,
            desc,
        )
        .with_sub_category(PHP_SUB_CATEGORY)
        // Same string as this install's inspection scope, so the report files it there.
        .with_scope(path.as_ref())
        .with_location(path.as_ref(), None)
        .with_remediation(rem),
    )
}

/// Scans locally installed PHP runtimes using the real filesystem root and home.
pub fn scan_php_runtimes(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let root = std::env::var_os("MACFLOW_SYSTEM_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    scan_php_runtimes_with_roots(ctx, &root, home.as_deref())
}

/// Scans PHP installs under `system_root` (Homebrew Cellars, MAMP) and `home`
/// (asdf, mise, phpenv). Never executes any discovered binary.
pub fn scan_php_runtimes_with_roots(
    ctx: &ScanContext,
    system_root: &Path,
    home: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    if !ctx.is_category_selected(Category::Security) {
        return (
            Vec::new(),
            vec![Inspection::skipped(
                Category::Security,
                Some(PHP_SUB_CATEGORY),
                Some("category not selected"),
            )],
        );
    }
    let installs = find_installs(system_root, home);
    if installs.is_empty() {
        return (
            Vec::new(),
            vec![Inspection::inspected(
                Category::Security,
                Some(PHP_SUB_CATEGORY),
                "user (no PHP installs found)",
            )],
        );
    }
    let findings = installs.iter().filter_map(inspect).collect();
    let inspections = installs
        .iter()
        .map(|i| {
            Inspection::inspected(
                Category::Security,
                Some(PHP_SUB_CATEGORY),
                i.path.to_string_lossy(),
            )
        })
        .collect();
    (findings, inspections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, InspectionStatus, Severity};
    use std::fs;
    use std::path::PathBuf;

    fn tmp(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("php_{label}_{}_{n}_{nanos}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn mk(root: &Path, rel: &str) {
        fs::create_dir_all(root.join(rel)).unwrap();
    }

    fn scan(root: &Path, home: &Path) -> (Vec<Finding>, Vec<Inspection>) {
        scan_php_runtimes_with_roots(&ScanContext::new(), root, Some(home))
    }

    #[test]
    fn vulnerable_homebrew_php_is_high_with_upgrade_command() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&root, "opt/homebrew/Cellar/php/8.4.20");
        let (f, i) = scan(&root, &home);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].category, Category::Security);
        assert!(f[0].title.contains("8.4.20"), "{}", f[0].title);
        assert!(f[0].description.contains("8.4.27"));
        assert!(f[0]
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("brew upgrade php"));
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Inspected { .. })));
    }

    #[test]
    fn patched_versions_and_homebrew_revisions_have_no_finding() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&root, "opt/homebrew/Cellar/php/8.4.27_1");
        mk(&root, "opt/homebrew/Cellar/php@8.3/8.3.36");
        mk(&root, "usr/local/Cellar/php@8.2/8.2.40");
        mk(&root, "opt/homebrew/Cellar/php/8.5.12");
        let (f, i) = scan(&root, &home);
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(i.len(), 4, "one inspection per install: {i:?}");
    }

    #[test]
    fn revision_suffix_does_not_hide_an_old_version() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&root, "opt/homebrew/Cellar/php@8.3/8.3.10_2");
        let (f, _) = scan(&root, &home);
        assert_eq!(f.len(), 1);
        assert!(f[0]
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("brew upgrade php@8.3"));
    }

    #[test]
    fn end_of_life_branches_are_flagged_as_unsupported() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&root, "opt/homebrew/Cellar/php@8.1/8.1.34");
        mk(&home, ".asdf/installs/php/7.4.33");
        let (f, _) = scan(&root, &home);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|x| x.severity == Severity::High));
        assert!(f.iter().all(|x| x.title.contains("no longer receives")));
    }

    #[test]
    fn version_managers_and_mamp_are_detected() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&home, ".asdf/installs/php/8.3.20");
        mk(&home, ".local/share/mise/installs/php/8.4.1");
        mk(&home, ".phpenv/versions/8.2.30");
        mk(&root, "Applications/MAMP/bin/php/php8.3.14");
        let (f, i) = scan(&root, &home);
        assert_eq!(f.len(), 4, "{f:?}");
        assert_eq!(i.len(), 4);
        let rems: Vec<String> = f.iter().filter_map(|x| x.remediation.clone()).collect();
        assert!(rems.iter().any(|r| r.contains("asdf")));
        assert!(rems.iter().any(|r| r.contains("mise")));
        assert!(rems.iter().any(|r| r.contains("phpenv")));
        assert!(rems.iter().any(|r| r.contains("MAMP")));
    }

    #[test]
    fn newer_branch_than_the_table_and_junk_dirs_are_not_flagged() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&root, "opt/homebrew/Cellar/php/8.6.0");
        mk(&root, "opt/homebrew/Cellar/php/not-a-version");
        mk(&root, "opt/homebrew/Cellar/phpmyadmin/5.2.1");
        mk(&root, "opt/homebrew/Cellar/php-cs-fixer/3.0.0");
        let (f, _) = scan(&root, &home);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn no_php_anywhere_is_one_honest_inspection_and_no_findings() {
        let (root, home) = (tmp("r"), tmp("h"));
        let (f, i) = scan(&root, &home);
        assert!(f.is_empty());
        assert_eq!(i.len(), 1);
        assert!(matches!(i[0].status, InspectionStatus::Inspected { .. }));
        assert_eq!(i[0].sub_category.as_deref(), Some(PHP_SUB_CATEGORY));
    }

    #[test]
    fn findings_render_under_php_runtime_with_several_installs() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&root, "opt/homebrew/Cellar/php/8.4.20");
        mk(&root, "opt/homebrew/Cellar/php@8.3/8.3.36");
        let (f, i) = scan(&root, &home);
        let r = crate::render_report(&crate::ScanResult::new(f, i, "2026-10-25T00:00:00Z"));
        assert!(!r.contains("scope unknown"), "{r}");
        assert!(!r.contains("Other findings"), "{r}");
    }

    #[test]
    fn category_not_selected_is_skipped() {
        let (root, home) = (tmp("r"), tmp("h"));
        mk(&root, "opt/homebrew/Cellar/php/8.4.20");
        let ctx = ScanContext::new().with_categories(vec![Category::AgentAudit]);
        let (f, i) = scan_php_runtimes_with_roots(&ctx, &root, Some(&home));
        assert!(f.is_empty());
        assert!(matches!(i[0].status, InspectionStatus::Skipped { .. }));
    }
}
