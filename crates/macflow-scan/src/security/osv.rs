use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const OSV_SUB_CATEGORY: &str = "Dependency vulnerabilities (OSV)";
const OSV_URL: &str = "https://api.osv.dev/v1/querybatch";
const BATCH_SIZE: usize = 1000;
const PARALLEL_REQUESTS: usize = 4;
const MAX_PAGE_ROUNDS: usize = 10;

/// Sends a JSON body to the OSV `querybatch` endpoint and returns the response body.
pub trait OsvTransport {
    fn post_querybatch(&self, body: &str) -> Result<String, String>;
}

/// Uses the system curl with a 15 s limit. The body goes over stdin, so package
/// names never appear in the process list.
pub struct CurlTransport;

impl OsvTransport for CurlTransport {
    fn post_querybatch(&self, body: &str) -> Result<String, String> {
        let mut child = Command::new("/usr/bin/curl")
            .args(["-sS", "--fail", "--max-time", "15", "-X", "POST"])
            .args([
                "-H",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                OSV_URL,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("could not start curl: {e}"))?;
        child
            .stdin
            .take()
            .ok_or("curl stdin unavailable")?
            .write_all(body.as_bytes())
            .map_err(|e| e.to_string())?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        String::from_utf8(out.stdout).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
}

fn pkg(ecosystem: &'static str, name: &str, version: &str) -> Package {
    Package {
        ecosystem,
        name: name.to_string(),
        version: version.to_string(),
    }
}

/// npm package-lock.json, lockfile versions 1, 2 and 3.
pub fn parse_package_lock(text: &str) -> Vec<Package> {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(packages) = v["packages"].as_object() {
        for (key, entry) in packages {
            let Some(idx) = key.rfind("node_modules/") else {
                continue; // "" is the root project; other keys are workspace folders
            };
            if entry["link"].as_bool() == Some(true) {
                continue;
            }
            if let Some(ver) = entry["version"].as_str() {
                out.push(pkg("npm", &key[idx + "node_modules/".len()..], ver));
            }
        }
    } else if let Some(deps) = v["dependencies"].as_object() {
        fn walk(deps: &serde_json::Map<String, Value>, out: &mut Vec<Package>) {
            for (name, entry) in deps {
                if let Some(ver) = entry["version"].as_str() {
                    out.push(pkg("npm", name, ver));
                }
                if let Some(nested) = entry["dependencies"].as_object() {
                    walk(nested, out);
                }
            }
        }
        walk(deps, &mut out);
    }
    out
}

/// Pipenv Pipfile.lock (`default` and `develop`, pinned with `==`).
pub fn parse_pipfile_lock(text: &str) -> Vec<Package> {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in ["default", "develop"] {
        for (name, entry) in v[section].as_object().into_iter().flatten() {
            if let Some(ver) = entry["version"].as_str().and_then(|s| s.strip_prefix("==")) {
                out.push(pkg("PyPI", name, ver));
            }
        }
    }
    out
}

/// Composer composer.lock (`packages` and `packages-dev`).
pub fn parse_composer_lock(text: &str) -> Vec<Package> {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for section in ["packages", "packages-dev"] {
        for entry in v[section].as_array().into_iter().flatten() {
            if let (Some(name), Some(ver)) = (entry["name"].as_str(), entry["version"].as_str()) {
                out.push(pkg("Packagist", name, ver.strip_prefix('v').unwrap_or(ver)));
            }
        }
    }
    out
}

type Parser = fn(&str) -> Vec<Package>;

const LOCKFILES: &[(&str, Parser)] = &[
    ("package-lock.json", parse_package_lock),
    ("Pipfile.lock", parse_pipfile_lock),
    ("composer.lock", parse_composer_lock),
];

/// Every package once, with the first lockfile it was found in.
fn collect_packages(project_dirs: &[PathBuf]) -> (BTreeMap<Package, PathBuf>, usize) {
    let mut pkgs = BTreeMap::new();
    let mut files = 0;
    for dir in project_dirs {
        for (file, parse) in LOCKFILES {
            let path = dir.join(file);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            files += 1;
            // npm's `0.0.1-security` releases are empty placeholders for removed packages.
            for p in parse(&text)
                .into_iter()
                .filter(|p| !p.version.ends_with("-security"))
            {
                pkgs.entry(p).or_insert_with(|| path.clone());
            }
        }
    }
    (pkgs, files)
}

fn query_body(packages: &[&Package], chunk: &[(usize, Option<String>)]) -> String {
    let queries: Vec<Value> = chunk
        .iter()
        .map(|(i, token)| {
            let p = packages[*i];
            let mut q = json!({"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version});
            if let Some(t) = token {
                q["page_token"] = json!(t);
            }
            q
        })
        .collect();
    json!({ "queries": queries }).to_string()
}

/// Vuln ids for one query, plus the token for its next page.
type QueryResult = (Vec<String>, Option<String>);

/// Returns, for each query in the chunk, its vuln ids and next page token.
fn run_chunk(
    packages: &[&Package],
    chunk: &[(usize, Option<String>)],
    transport: &(dyn OsvTransport + Sync),
) -> Result<Vec<QueryResult>, String> {
    let reply = transport.post_querybatch(&query_body(packages, chunk))?;
    let v: Value = serde_json::from_str(&reply).map_err(|e| format!("bad OSV reply: {e}"))?;
    let results = v["results"].as_array().ok_or("bad OSV reply: no results")?;
    if results.len() != chunk.len() {
        return Err("bad OSV reply: result count mismatch".into());
    }
    Ok(results
        .iter()
        .map(|r| {
            let ids = r["vulns"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v["id"].as_str().map(str::to_string))
                .collect();
            (ids, r["next_page_token"].as_str().map(str::to_string))
        })
        .collect())
}

/// Queries OSV for every package (batches sent a few at a time, in parallel),
/// following `next_page_token`. Returns vuln ids per package.
fn lookup(
    packages: &[&Package],
    transport: &(dyn OsvTransport + Sync),
) -> Result<Vec<Vec<String>>, String> {
    let mut ids: Vec<Vec<String>> = vec![Vec::new(); packages.len()];
    let mut pending: Vec<(usize, Option<String>)> =
        (0..packages.len()).map(|i| (i, None)).collect();
    for _ in 0..MAX_PAGE_ROUNDS {
        if pending.is_empty() {
            break;
        }
        let chunks: Vec<&[(usize, Option<String>)]> = pending.chunks(BATCH_SIZE).collect();
        let mut next = Vec::new();
        for group in chunks.chunks(PARALLEL_REQUESTS) {
            let replies: Vec<_> = std::thread::scope(|s| {
                let handles: Vec<_> = group
                    .iter()
                    .map(|chunk| s.spawn(move || run_chunk(packages, chunk, transport)))
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .unwrap_or_else(|_| Err("OSV lookup thread failed".into()))
                    })
                    .collect()
            });
            for (chunk, reply) in group.iter().zip(replies) {
                for ((i, _), (found, token)) in chunk.iter().zip(reply?) {
                    ids[*i].extend(found);
                    if let Some(t) = token {
                        next.push((*i, Some(t)));
                    }
                }
            }
        }
        pending = next;
    }
    Ok(ids)
}

fn malicious_finding(p: &Package, lockfile: &Path, ids: &[String]) -> Finding {
    Finding::new(
        "osv-malicious-package",
        format!("Known malicious package: {} {} ({})", p.name, p.version, p.ecosystem),
        Category::Security,
        Severity::Critical,
        format!("OSV lists {}. Details: https://osv.dev/vulnerability/{}", ids.join(", "), ids[0]),
    )
    .with_sub_category(OSV_SUB_CATEGORY)
    .with_scope("proj")
    .with_location(lockfile.to_string_lossy().as_ref(), None)
    .with_remediation(
        "Remove this version now, reinstall from a known-good release, and rotate credentials that \
         were available where it was installed or run.",
    )
}

/// One finding per lockfile, so a big dependency tree doesn't bury the report.
fn grouped_finding(lockfile: &Path, mut hits: Vec<(&Package, &Vec<String>)>) -> Finding {
    hits.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
    let shown: Vec<String> = hits
        .iter()
        .take(5)
        .map(|(p, ids)| {
            let first: Vec<&str> = ids.iter().take(3).map(String::as_str).collect();
            format!("{} {} ({})", p.name, p.version, first.join(", "))
        })
        .collect();
    let more = if hits.len() > 5 {
        format!("; {} more", hits.len() - 5)
    } else {
        String::new()
    };
    let file = lockfile
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let audit = match file.as_str() {
        "composer.lock" => "composer audit",
        "Pipfile.lock" => "pip-audit",
        _ => "npm audit",
    };
    Finding::new(
        "osv-vulnerable-packages",
        format!(
            "{} packages with known vulnerabilities in {file}",
            hits.len()
        ),
        Category::Security,
        Severity::Medium,
        format!(
            "Most affected: {}{more}. Details for each id: https://osv.dev/vulnerability/<id>",
            shown.join("; ")
        ),
    )
    .with_sub_category(OSV_SUB_CATEGORY)
    .with_scope("proj")
    .with_location(lockfile.to_string_lossy().as_ref(), None)
    .with_remediation(format!(
        "Run `{audit}` in this project to see fixed versions, then upgrade."
    ))
}

pub fn scan_osv(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let dirs = crate::agent::tasks_secrets::project_dirs(ctx);
    if !ctx.offline && ctx.is_category_selected(Category::Security) {
        eprintln!("Looking up lockfile dependencies in OSV (sends package names and versions only; --offline skips this)...");
    }
    scan_osv_with(ctx, &dirs, &CurlTransport)
}

pub fn scan_osv_with(
    ctx: &ScanContext,
    project_dirs: &[PathBuf],
    transport: &(dyn OsvTransport + Sync),
) -> (Vec<Finding>, Vec<Inspection>) {
    let skip = |reason: &str| {
        (
            Vec::new(),
            vec![Inspection::skipped(
                Category::Security,
                Some(OSV_SUB_CATEGORY),
                Some(reason),
            )],
        )
    };
    if !ctx.is_category_selected(Category::Security) {
        return skip("category not selected");
    }
    if ctx.offline {
        return skip("offline mode");
    }
    let (pkgs, files) = collect_packages(project_dirs);
    if pkgs.is_empty() {
        return (
            Vec::new(),
            vec![Inspection::inspected(
                Category::Security,
                Some(OSV_SUB_CATEGORY),
                format!("proj ({files} lockfiles, no packages to look up)"),
            )],
        );
    }
    let list: Vec<&Package> = pkgs.keys().collect();
    match lookup(&list, transport) {
        Err(e) => skip(&format!("lookup failed: {e}")),
        Ok(ids) => {
            let mut findings = Vec::new();
            let mut by_file: BTreeMap<&PathBuf, Vec<(&Package, &Vec<String>)>> = BTreeMap::new();
            for (p, v) in list.iter().zip(&ids).filter(|(_, v)| !v.is_empty()) {
                let file = &pkgs[*p];
                if v.iter().any(|id| id.starts_with("MAL-")) {
                    findings.push(malicious_finding(p, file, v));
                } else {
                    by_file.entry(file).or_default().push((p, v));
                }
            }
            findings.extend(
                by_file
                    .into_iter()
                    .map(|(f, hits)| grouped_finding(f, hits)),
            );
            (
                findings,
                vec![Inspection::inspected(
                    Category::Security,
                    Some(OSV_SUB_CATEGORY),
                    format!("proj ({} packages from {files} lockfiles)", list.len()),
                )],
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, InspectionStatus, Severity};
    use serde_json::{json, Value};
    use std::fs;
    use std::sync::Mutex;

    type Reply = Box<dyn Fn(&Value) -> Result<Value, String> + Send + Sync>;

    /// Records every request body and answers from a closure.
    struct Fake {
        bodies: Mutex<Vec<String>>,
        reply: Reply,
    }

    impl Fake {
        fn new(reply: impl Fn(&Value) -> Result<Value, String> + Send + Sync + 'static) -> Self {
            Fake {
                bodies: Mutex::new(Vec::new()),
                reply: Box::new(reply),
            }
        }
    }

    impl OsvTransport for Fake {
        fn post_querybatch(&self, body: &str) -> Result<String, String> {
            self.bodies.lock().unwrap().push(body.to_string());
            let v: Value = serde_json::from_str(body).unwrap();
            (self.reply)(&v).map(|r| r.to_string())
        }
    }

    fn no_vulns(req: &Value) -> Result<Value, String> {
        let n = req["queries"].as_array().unwrap().len();
        Ok(json!({ "results": vec![json!({}); n] }))
    }

    fn tmp() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("osv_{}_{n}_{nanos}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(p: &[Package]) -> Vec<String> {
        let mut v: Vec<String> = p
            .iter()
            .map(|p| format!("{}:{}@{}", p.ecosystem, p.name, p.version))
            .collect();
        v.sort();
        v
    }

    #[test]
    fn test_osv_parses_package_lock_v3_including_nested_and_scoped() {
        let lock = r#"{"lockfileVersion":3,"packages":{
            "":{"name":"app","version":"1.0.0"},
            "node_modules/left-pad":{"version":"1.3.0"},
            "node_modules/@scope/pkg":{"version":"2.0.0"},
            "node_modules/a/node_modules/b":{"version":"0.1.0"},
            "packages/local":{"version":"9.9.9"},
            "node_modules/linked":{"link":true,"resolved":"packages/local"}}}"#;
        assert_eq!(
            names(&parse_package_lock(lock)),
            vec!["npm:@scope/pkg@2.0.0", "npm:b@0.1.0", "npm:left-pad@1.3.0"]
        );
    }

    #[test]
    fn test_osv_parses_package_lock_v1_recursively() {
        let lock = r#"{"lockfileVersion":1,"dependencies":{
            "a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}"#;
        assert_eq!(
            names(&parse_package_lock(lock)),
            vec!["npm:a@1.0.0", "npm:b@2.0.0"]
        );
    }

    #[test]
    fn test_osv_parses_pipfile_and_composer_locks() {
        let pip = r#"{"default":{"requests":{"version":"==2.31.0"}},"develop":{"pytest":{"version":"==8.0.0"},"nover":{}}}"#;
        assert_eq!(
            names(&parse_pipfile_lock(pip)),
            vec!["PyPI:pytest@8.0.0", "PyPI:requests@2.31.0"]
        );
        let composer = r#"{"packages":[{"name":"laravel-lang/lang","version":"v15.1.0"}],
            "packages-dev":[{"name":"phpunit/phpunit","version":"10.5.0"}]}"#;
        assert_eq!(
            names(&parse_composer_lock(composer)),
            vec![
                "Packagist:laravel-lang/lang@15.1.0",
                "Packagist:phpunit/phpunit@10.5.0"
            ]
        );
    }

    #[test]
    fn test_osv_malformed_lockfiles_yield_nothing() {
        assert!(parse_package_lock("not json").is_empty());
        assert!(parse_pipfile_lock("{").is_empty());
        assert!(parse_composer_lock("[]").is_empty());
    }

    fn project_with_lock() -> PathBuf {
        let d = tmp();
        fs::write(
            d.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.0.0"},"node_modules/old":{"version":"0.1.0"},"node_modules/fine":{"version":"3.0.0"}}}"#,
        )
        .unwrap();
        d
    }

    #[test]
    fn test_osv_sends_only_name_version_ecosystem() {
        let d = project_with_lock();
        let fake = Fake::new(no_vulns);
        scan_osv_with(&ScanContext::new(), std::slice::from_ref(&d), &fake);
        let bodies = fake.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1);
        assert!(
            !bodies[0].contains(&d.to_string_lossy().to_string()),
            "path leaked"
        );
        let v: Value = serde_json::from_str(&bodies[0]).unwrap();
        for q in v["queries"].as_array().unwrap() {
            let mut keys: Vec<&String> = q.as_object().unwrap().keys().collect();
            keys.sort();
            assert_eq!(keys, vec!["package", "version"]);
            let mut pk: Vec<&String> = q["package"].as_object().unwrap().keys().collect();
            pk.sort();
            assert_eq!(pk, vec!["ecosystem", "name"]);
        }
    }

    #[test]
    fn test_osv_findings_malicious_is_critical_vulnerable_grouped_per_lockfile() {
        let d = project_with_lock();
        let fake = Fake::new(|req| {
            let res: Vec<Value> = req["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| match q["package"]["name"].as_str().unwrap() {
                    "evil" => json!({"vulns":[{"id":"MAL-2026-1"}]}),
                    "old" => json!({"vulns":[{"id":"GHSA-aaaa-bbbb-cccc"},{"id":"CVE-2026-1"}]}),
                    "fine" => json!({"vulns":[{"id":"GHSA-zzzz"}]}),
                    _ => json!({}),
                })
                .collect();
            Ok(json!({ "results": res }))
        });
        let (f, i) = scan_osv_with(&ScanContext::new(), &[d], &fake);
        assert_eq!(f.len(), 2, "one malicious + one grouped finding: {f:?}");
        let evil = f.iter().find(|x| x.title.contains("evil")).unwrap();
        assert_eq!(evil.severity, Severity::Critical);
        let grouped = f
            .iter()
            .find(|x| x.id == "osv-vulnerable-packages")
            .unwrap();
        assert_eq!(grouped.severity, Severity::Medium);
        assert!(grouped.title.starts_with("2 packages"), "{}", grouped.title);
        assert!(grouped.description.contains("old 0.1.0"));
        assert!(grouped.description.contains("GHSA-aaaa-bbbb-cccc"));
        assert!(grouped
            .file_path
            .as_ref()
            .unwrap()
            .ends_with("package-lock.json"));
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Inspected { .. })));
        assert_eq!(f[0].category, Category::Security);
    }

    #[test]
    fn test_osv_findings_render_under_their_sub_category() {
        let d = project_with_lock();
        let fake = Fake::new(|req| {
            let n = req["queries"].as_array().unwrap().len();
            Ok(json!({ "results": vec![json!({"vulns":[{"id":"GHSA-1"}]}); n] }))
        });
        let (f, i) = scan_osv_with(&ScanContext::new(), &[d], &fake);
        let r = crate::render_report(&crate::ScanResult::new(f, i, "2026-10-25T00:00:00Z"));
        assert!(!r.contains("Other findings"), "{r}");
        assert!(!r.contains("scope unknown"), "{r}");
    }

    #[test]
    fn test_osv_npm_security_placeholders_are_not_reported() {
        let d = tmp();
        fs::write(
            d.join("package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"node_modules/fs":{"version":"0.0.1-security"}}}"#,
        )
        .unwrap();
        let fake = Fake::new(|req| {
            let n = req["queries"].as_array().unwrap().len();
            Ok(json!({ "results": vec![json!({"vulns":[{"id":"MAL-2022-1"}]}); n] }))
        });
        let (f, _) = scan_osv_with(&ScanContext::new(), &[d], &fake);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn test_osv_large_trees_are_split_into_batches_and_attributed_correctly() {
        let d = tmp();
        let entries: Vec<String> = (0..2500)
            .map(|i| format!(r#""node_modules/p{i}":{{"version":"1.0.0"}}"#))
            .collect();
        fs::write(
            d.join("package-lock.json"),
            format!(
                r#"{{"lockfileVersion":3,"packages":{{{}}}}}"#,
                entries.join(",")
            ),
        )
        .unwrap();
        let fake = Fake::new(|req| {
            let res: Vec<Value> = req["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| match q["package"]["name"].as_str().unwrap() {
                    "p1999" => json!({"vulns":[{"id":"GHSA-p1999"}]}),
                    _ => json!({}),
                })
                .collect();
            Ok(json!({ "results": res }))
        });
        let (f, _) = scan_osv_with(&ScanContext::new(), &[d], &fake);
        let bodies = fake.bodies.lock().unwrap();
        assert_eq!(bodies.len(), 3, "2500 queries -> 3 batches of up to 1000");
        assert!(bodies
            .iter()
            .all(|b| serde_json::from_str::<Value>(b).unwrap()["queries"]
                .as_array()
                .unwrap()
                .len()
                <= 1000));
        assert_eq!(f.len(), 1);
        assert!(
            f[0].description.contains("p1999 1.0.0 (GHSA-p1999)"),
            "{}",
            f[0].description
        );
    }

    #[test]
    fn test_osv_follows_next_page_token() {
        let d = project_with_lock();
        let fake = Fake::new(|req| {
            let qs = req["queries"].as_array().unwrap();
            let res: Vec<Value> = qs
                .iter()
                .map(|q| {
                    let name = q["package"]["name"].as_str().unwrap();
                    match (name, q.get("page_token").and_then(|t| t.as_str())) {
                        ("old", None) => json!({"vulns":[{"id":"GHSA-1"}],"next_page_token":"tok"}),
                        ("old", Some("tok")) => json!({"vulns":[{"id":"GHSA-2"}]}),
                        _ => json!({}),
                    }
                })
                .collect();
            Ok(json!({ "results": res }))
        });
        let (f, _) = scan_osv_with(&ScanContext::new(), &[d], &fake);
        assert_eq!(fake.bodies.lock().unwrap().len(), 2);
        let grouped = f
            .iter()
            .find(|x| x.id == "osv-vulnerable-packages")
            .unwrap();
        assert!(grouped.description.contains("GHSA-1") && grouped.description.contains("GHSA-2"));
    }

    #[test]
    fn test_osv_dedupes_packages_across_lockfiles() {
        let a = project_with_lock();
        let b = project_with_lock();
        let fake = Fake::new(no_vulns);
        scan_osv_with(&ScanContext::new(), &[a, b], &fake);
        let v: Value = serde_json::from_str(&fake.bodies.lock().unwrap()[0]).unwrap();
        assert_eq!(v["queries"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_osv_offline_makes_zero_requests_and_reports_not_checked() {
        let d = project_with_lock();
        let fake = Fake::new(no_vulns);
        let (f, i) = scan_osv_with(&ScanContext::new().with_offline(true), &[d], &fake);
        assert!(fake.bodies.lock().unwrap().is_empty());
        assert!(f.is_empty());
        assert!(
            matches!(&i[0].status, InspectionStatus::Skipped { reason } if reason.as_deref() == Some("offline mode"))
        );
    }

    #[test]
    fn test_osv_network_failure_reports_not_checked() {
        let d = project_with_lock();
        let fake = Fake::new(|_| Err("timed out".into()));
        let (f, i) = scan_osv_with(&ScanContext::new(), &[d], &fake);
        assert!(f.is_empty());
        assert!(
            matches!(&i[0].status, InspectionStatus::Skipped { reason } if reason.as_deref().unwrap_or("").contains("lookup failed"))
        );
    }

    #[test]
    fn test_osv_no_lockfiles_makes_no_request() {
        let fake = Fake::new(no_vulns);
        let (f, i) = scan_osv_with(&ScanContext::new(), &[tmp()], &fake);
        assert!(fake.bodies.lock().unwrap().is_empty());
        assert!(f.is_empty());
        assert_eq!(i.len(), 1);
        assert!(matches!(i[0].status, InspectionStatus::Inspected { .. }));
    }
}
