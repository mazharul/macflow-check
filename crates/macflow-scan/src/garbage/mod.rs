use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const CACHES_SUB_CATEGORY: &str = "Developer caches";
pub const NODE_MODULES_SUB_CATEGORY: &str = "Stale node_modules";

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const REPORT_THRESHOLD: u64 = 100 * MIB;
const STALE_AFTER: Duration = Duration::from_secs(90 * 86400);

/// (label, folder under home, how to reclaim it)
const CACHES: &[(&str, &str, &str)] = &[
    ("Xcode DerivedData", "Library/Developer/Xcode/DerivedData",
     "Xcode rebuilds it on demand. Delete it from Xcode > Settings > Locations, or run `rm -rf ~/Library/Developer/Xcode/DerivedData`."),
    ("Xcode Archives", "Library/Developer/Xcode/Archives",
     "Archives are builds you may still need to re-submit or symbolicate crashes. Delete old ones from Xcode's Organizer."),
    ("Xcode device support files", "Library/Developer/Xcode/iOS DeviceSupport",
     "Xcode downloads these again when a device connects. Delete folders for iOS versions you no longer test on."),
    ("Simulator caches", "Library/Developer/CoreSimulator/Caches",
     "Run `xcrun simctl delete unavailable`, then delete this cache folder; the simulator rebuilds it."),
    ("npm cache", ".npm/_cacache", "Run `npm cache clean --force`."),
    ("Homebrew cache", "Library/Caches/Homebrew", "Run `brew cleanup -s`."),
    ("pip cache", "Library/Caches/pip", "Run `pip cache purge`."),
    ("Yarn cache", "Library/Caches/Yarn", "Run `yarn cache clean`."),
];

/// Bytes actually allocated on disk under `path`, like `du -k`: allocated blocks
/// (so sparse files count only what they use), symlinks not followed, each
/// hard-linked file counted once. Directories are walked by several threads,
/// since big caches are mostly metadata calls.
pub fn disk_usage(path: &Path) -> u64 {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.file_type().is_symlink() {
        return 0;
    }
    let total = AtomicU64::new(meta.blocks() * 512);
    if !meta.is_dir() {
        return total.into_inner();
    }

    let queue = Mutex::new(vec![path.to_path_buf()]);
    let seen = Mutex::new(HashSet::new());
    // Directories queued or being read; the walk is done when this reaches zero.
    let pending = AtomicUsize::new(1);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let next = queue.lock().unwrap().pop();
                let Some(dir) = next else {
                    if pending.load(Ordering::Acquire) == 0 {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_micros(200));
                    continue;
                };
                let mut subdirs = Vec::new();
                let mut bytes = 0;
                for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                    // DirEntry::metadata does not follow symlinks.
                    let Ok(m) = entry.metadata() else { continue };
                    if m.file_type().is_symlink() {
                        continue;
                    }
                    if m.nlink() > 1
                        && !m.is_dir()
                        && !seen.lock().unwrap().insert((m.dev(), m.ino()))
                    {
                        continue;
                    }
                    bytes += m.blocks() * 512;
                    if m.is_dir() {
                        subdirs.push(entry.path());
                    }
                }
                total.fetch_add(bytes, Ordering::Relaxed);
                if !subdirs.is_empty() {
                    pending.fetch_add(subdirs.len(), Ordering::AcqRel);
                    queue.lock().unwrap().extend(subdirs);
                }
                pending.fetch_sub(1, Ordering::AcqRel);
            });
        }
    });
    total.into_inner()
}

/// Info below 1 GiB, Low from 1 GiB. Garbage never outranks a real risk.
pub(crate) fn severity_for(bytes: u64) -> Severity {
    if bytes >= GIB {
        Severity::Low
    } else {
        Severity::Info
    }
}

fn human(bytes: u64) -> String {
    if bytes >= GIB {
        format!("{:.1} GB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MB", bytes / MIB)
    }
}

/// The project's git directory: `.git` itself, or where a `.git` file's
/// `gitdir:` line points (worktrees and submodules), relative to the project.
fn git_dir(project: &Path) -> PathBuf {
    let dot_git = project.join(".git");
    std::fs::read_to_string(&dot_git)
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("gitdir:"))
                .map(|d| project.join(d.trim()))
        })
        .unwrap_or(dot_git)
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

fn scan_caches(home: &Path) -> (Vec<Finding>, Vec<Inspection>) {
    let mut findings = Vec::new();
    let mut inspections = Vec::new();
    for (label, rel, fix) in CACHES {
        let dir = home.join(rel);
        if !dir.is_dir() {
            continue;
        }
        // A symlinked cache root (moved to another disk) is measured at its target.
        let bytes = disk_usage(&std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone()));
        // The finding carries the same scope label so the report files it under this inspection.
        let scope = format!("user: {label} ({})", human(bytes));
        inspections.push(Inspection::inspected(
            Category::Garbage,
            Some(CACHES_SUB_CATEGORY),
            scope.clone(),
        ));
        if bytes >= REPORT_THRESHOLD {
            findings.push(
                Finding::new(
                    "garbage-dev-cache",
                    format!("{label}: {} reclaimable", human(bytes)),
                    Category::Garbage,
                    severity_for(bytes),
                    format!("{label} uses {} on disk.", human(bytes)),
                )
                .with_sub_category(CACHES_SUB_CATEGORY)
                .with_scope(scope)
                .with_location(dir.to_string_lossy().as_ref(), None)
                .with_remediation(*fix),
            );
        }
    }
    if inspections.is_empty() {
        inspections.push(Inspection::inspected(
            Category::Garbage,
            Some(CACHES_SUB_CATEGORY),
            "user (no developer caches found)",
        ));
    }
    (findings, inspections)
}

fn scan_node_modules(project_dirs: &[PathBuf], now: SystemTime) -> (Vec<Finding>, Vec<Inspection>) {
    let mut stale: Vec<(PathBuf, u64)> = Vec::new();
    let mut seen = HashSet::new();
    let mut checked = 0;
    for dir in project_dirs {
        let nm = dir.join("node_modules");
        let is_real_dir = std::fs::symlink_metadata(&nm).is_ok_and(|m| m.is_dir());
        if !is_real_dir || !seen.insert(nm.clone()) {
            continue;
        }
        checked += 1;
        let last_used = [
            nm.clone(),
            dir.join("package.json"),
            dir.join("package-lock.json"),
            // Commits and checkouts touch these, so an active repo with stable deps stays fresh.
            git_dir(dir).join("index"),
            git_dir(dir).join("HEAD"),
        ]
        .iter()
        .filter_map(|p| mtime(p))
        .max();
        let is_stale = last_used
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age >= STALE_AFTER);
        if is_stale {
            stale.push((dir.clone(), disk_usage(&nm)));
        }
    }
    let inspection = Inspection::inspected(
        Category::Garbage,
        Some(NODE_MODULES_SUB_CATEGORY),
        format!("proj ({checked} node_modules folders)"),
    );
    let total: u64 = stale.iter().map(|(_, b)| b).sum();
    if total < REPORT_THRESHOLD {
        return (Vec::new(), vec![inspection]);
    }
    stale.sort_by_key(|a| std::cmp::Reverse(a.1));
    let top: Vec<String> = stale
        .iter()
        .take(5)
        .map(|(d, b)| format!("{} ({})", d.display(), human(*b)))
        .collect();
    let finding = Finding::new(
        "garbage-stale-node-modules",
        format!(
            "{} in node_modules across {} untouched for 90+ days",
            human(total),
            if stale.len() == 1 {
                "1 project".to_string()
            } else {
                format!("{} projects", stale.len())
            }
        ),
        Category::Garbage,
        severity_for(total),
        format!("Largest: {}.", top.join(", ")),
    )
    .with_sub_category(NODE_MODULES_SUB_CATEGORY)
    .with_scope("proj")
    .with_remediation(
        "Delete node_modules in projects you are not working on; `npm install` restores it.",
    );
    (vec![finding], vec![inspection])
}

pub fn scan_garbage(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    let dirs = crate::agent::tasks_secrets::project_dirs(ctx);
    scan_garbage_with(ctx, home.as_deref(), &dirs, SystemTime::now())
}

pub fn scan_garbage_with(
    ctx: &ScanContext,
    home: Option<&Path>,
    project_dirs: &[PathBuf],
    now: SystemTime,
) -> (Vec<Finding>, Vec<Inspection>) {
    if !ctx.is_category_selected(Category::Garbage) {
        let skip =
            |sub| Inspection::skipped(Category::Garbage, Some(sub), Some("category not selected"));
        return (
            Vec::new(),
            vec![skip(CACHES_SUB_CATEGORY), skip(NODE_MODULES_SUB_CATEGORY)],
        );
    }
    let (mut findings, mut inspections) = match home {
        Some(h) => scan_caches(h),
        None => (
            Vec::new(),
            vec![Inspection::skipped(
                Category::Garbage,
                Some(CACHES_SUB_CATEGORY),
                Some("home directory unavailable"),
            )],
        ),
    };
    let (f, i) = scan_node_modules(project_dirs, now);
    findings.extend(f);
    inspections.extend(i);
    (findings, inspections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, InspectionStatus, Severity};
    use std::fs;
    use std::time::Duration;

    const MB: usize = 1024 * 1024;

    fn tmp() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("garb_{}_{n}_{nanos}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_mb(path: &Path, mb: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![7u8; mb * MB]).unwrap();
    }

    fn du_k(path: &Path) -> u64 {
        let out = std::process::Command::new("du")
            .arg("-sk")
            .arg(path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    #[test]
    fn test_garbage_disk_usage_matches_du_within_one_percent() {
        let d = tmp();
        write_mb(&d.join("a/big.bin"), 3);
        fs::write(d.join("a/small.txt"), "x").unwrap();
        write_mb(&d.join("b/c/mid.bin"), 1);
        let ours = disk_usage(&d) / 1024;
        let theirs = du_k(&d);
        let diff = ours.abs_diff(theirs) as f64;
        assert!(diff <= theirs as f64 * 0.01, "ours={ours}K du={theirs}K");
    }

    #[test]
    fn test_garbage_disk_usage_skips_symlinks_and_counts_hardlinks_once() {
        let d = tmp();
        let outside = tmp();
        write_mb(&outside.join("huge.bin"), 4);
        write_mb(&d.join("one.bin"), 2);
        std::os::unix::fs::symlink(&outside, d.join("link")).unwrap();
        fs::hard_link(d.join("one.bin"), d.join("same.bin")).unwrap();
        let mb = disk_usage(&d) / MB as u64;
        assert_eq!(mb, 2, "symlink target or hard link was counted");
    }

    #[test]
    fn test_garbage_reports_large_xcode_and_cache_dirs() {
        let home = tmp();
        write_mb(
            &home.join("Library/Developer/Xcode/DerivedData/App-abc/Build/x.o"),
            120,
        );
        write_mb(&home.join(".npm/_cacache/content/y"), 101);
        write_mb(&home.join("Library/Caches/Homebrew/z.tar.gz"), 5); // below threshold
        let (f, i) = scan_garbage_with(&ScanContext::new(), Some(&home), &[], SystemTime::now());
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert_eq!(f.len(), 2, "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("Xcode DerivedData")));
        assert!(titles.iter().any(|t| t.contains("npm cache")));
        assert!(f.iter().all(|x| x.category == Category::Garbage));
        assert!(f.iter().all(|x| x.severity == Severity::Info));
        assert!(f.iter().all(|x| x.remediation.is_some()));
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Inspected { .. })));
    }

    #[test]
    fn test_garbage_sparse_files_count_only_allocated_blocks() {
        let home = tmp();
        // A sparse file allocates nothing, so it must not count as 1 GB.
        let sparse = home.join("Library/Developer/Xcode/DerivedData/sparse.bin");
        fs::create_dir_all(sparse.parent().unwrap()).unwrap();
        fs::File::create(&sparse).unwrap().set_len(2 << 30).unwrap();
        let (f, _) = scan_garbage_with(&ScanContext::new(), Some(&home), &[], SystemTime::now());
        assert!(f.is_empty(), "sparse file counted as allocated: {f:?}");
    }

    fn project_with_node_modules(root: &Path, name: &str, mb: usize) -> PathBuf {
        let p = root.join(name);
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("package.json"), "{}").unwrap();
        write_mb(&p.join("node_modules/dep/index.js"), mb);
        p
    }

    #[test]
    fn test_garbage_stale_node_modules_older_than_90_days_grouped() {
        let root = tmp();
        let old = project_with_node_modules(&root, "old-app", 60);
        let old2 = project_with_node_modules(&root, "older-app", 50);
        let fresh = project_with_node_modules(&root, "fresh-app", 70);
        let now = SystemTime::now() + Duration::from_secs(91 * 86400);
        // fresh-app was touched "today" relative to the fake clock.
        let touch = |p: &Path, t: SystemTime| {
            fs::File::open(p).unwrap().set_modified(t).unwrap();
        };
        touch(&fresh.join("node_modules"), now);
        touch(&fresh.join("package.json"), now);
        let dirs = vec![root.clone(), old.clone(), old2.clone(), fresh.clone()];
        let (f, _) = scan_garbage_with(&ScanContext::new(), None, &dirs, now);
        let nm: Vec<&Finding> = f
            .iter()
            .filter(|x| x.sub_category.as_deref() == Some(NODE_MODULES_SUB_CATEGORY))
            .collect();
        assert_eq!(nm.len(), 1, "{f:?}");
        assert!(nm[0].title.contains("2 projects"), "{}", nm[0].title);
        assert!(nm[0].description.contains("old-app"));
        assert!(!nm[0].description.contains("fresh-app"));
    }

    #[test]
    fn test_garbage_symlinked_cache_root_counts_its_target() {
        // DerivedData moved to an external disk and symlinked back is still reclaimable.
        let home = tmp();
        let target = tmp().join("ExternalDerivedData");
        write_mb(&target.join("App-abc/x.o"), 120);
        let link = home.join("Library/Developer/Xcode/DerivedData");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (f, _) = scan_garbage_with(&ScanContext::new(), Some(&home), &[], SystemTime::now());
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].title.contains("Xcode DerivedData: 120 MB"),
            "{}",
            f[0].title
        );
    }

    #[test]
    fn test_garbage_recent_git_activity_keeps_node_modules_fresh() {
        // Stable dependencies but commits this week: the project is in use.
        let root = tmp();
        let active = project_with_node_modules(&root, "active-app", 120);
        let index = active.join(".git/index");
        fs::create_dir_all(index.parent().unwrap()).unwrap();
        fs::write(&index, "").unwrap();
        let now = SystemTime::now() + Duration::from_secs(91 * 86400);
        fs::File::open(&index).unwrap().set_modified(now).unwrap();
        let (f, _) = scan_garbage_with(&ScanContext::new(), None, &[active], now);
        assert!(f.is_empty(), "active project reported stale: {f:?}");
    }

    #[test]
    fn test_garbage_git_activity_followed_through_gitdir_file() {
        // Worktrees and submodules have a `.git` file pointing at the real git dir.
        let root = tmp();
        let active = project_with_node_modules(&root, "wt-app", 120);
        let gitdir = root.join("main-repo/.git/worktrees/wt-app");
        fs::create_dir_all(&gitdir).unwrap();
        fs::write(
            active.join(".git"),
            "gitdir: ../main-repo/.git/worktrees/wt-app\n",
        )
        .unwrap();
        let index = gitdir.join("index");
        fs::write(&index, "").unwrap();
        let now = SystemTime::now() + Duration::from_secs(91 * 86400);
        fs::File::open(&index).unwrap().set_modified(now).unwrap();
        let (f, _) = scan_garbage_with(&ScanContext::new(), None, &[active], now);
        assert!(
            f.is_empty(),
            "worktree with recent git activity reported stale: {f:?}"
        );
    }

    #[test]
    fn test_garbage_single_stale_project_title_is_singular() {
        let root = tmp();
        let old = project_with_node_modules(&root, "old-app", 120);
        let now = SystemTime::now() + Duration::from_secs(91 * 86400);
        let (f, _) = scan_garbage_with(&ScanContext::new(), None, &[old], now);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].title.contains("across 1 project untouched"),
            "{}",
            f[0].title
        );
    }

    #[test]
    fn test_garbage_severity_threshold() {
        assert_eq!(severity_for(500 * MB as u64), Severity::Info);
        assert_eq!(severity_for(1 << 30), Severity::Low);
        assert_eq!(severity_for(80 << 30), Severity::Low);
    }

    #[test]
    fn test_garbage_findings_render_under_their_sub_category() {
        let home = tmp();
        write_mb(&home.join(".npm/_cacache/a"), 101);
        write_mb(&home.join("Library/Caches/pip/b"), 101);
        let root = tmp();
        let p = project_with_node_modules(&root, "old", 101);
        let now = SystemTime::now() + Duration::from_secs(91 * 86400);
        let (f, i) = scan_garbage_with(&ScanContext::new(), Some(&home), &[p], now);
        let r = crate::render_report(&crate::ScanResult::new(f, i, "2026-10-25T00:00:00Z"));
        assert!(!r.contains("scope unknown"), "{r}");
        assert!(!r.contains("Other findings"), "{r}");
    }

    #[test]
    fn test_garbage_nothing_found_is_honest_and_quiet() {
        let home = tmp();
        let (f, i) = scan_garbage_with(&ScanContext::new(), Some(&home), &[], SystemTime::now());
        assert!(f.is_empty());
        assert!(!i.is_empty());
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Inspected { .. })));
    }

    #[test]
    fn test_garbage_category_not_selected_is_skipped() {
        let ctx = ScanContext::new().with_categories(vec![Category::Security]);
        let (f, i) = scan_garbage_with(&ctx, Some(&tmp()), &[], SystemTime::now());
        assert!(f.is_empty());
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Skipped { .. })));
    }
}
