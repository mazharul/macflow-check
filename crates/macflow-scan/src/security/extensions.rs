use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};

pub const EXT_SUB_CATEGORY: &str = "Editor extensions";
pub const MALWARE_FILES_SUB_CATEGORY: &str = "Known malware files";

/// Extension folders for VS Code and its forks (Insiders, VSCodium, Cursor, Windsurf).
const EDITOR_DIRS: &[(&str, &str)] = &[
    (".vscode", "VS Code"),
    (".vscode-insiders", "VS Code Insiders"),
    (".vscode-oss", "VSCodium"),
    (".cursor", "Cursor"),
    (".windsurf", "Windsurf"),
];

/// Known-compromised releases, each from a published incident report.
/// `None` for versions means every release is affected.
struct Bad {
    id: &'static str,
    versions: Option<&'static [&'static str]>,
    incident: &'static str,
}

const BAD_EXTENSIONS: &[Bad] = &[
    Bad {
        id: "nrwl.angular-console",
        versions: Some(&["18.95.0"]),
        incident: "Nx Console 18.95.0 shipped a credential stealer on 18 May 2026 (GHSA-c9j4-9m59-847w; \
                   https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised). 18.100.0 is the fixed release.",
    },
    Bad {
        id: "oorzc.ssh-tools",
        versions: None,
        incident: "GlassWorm loader in Open VSX releases, January 2026; the extension was removed entirely \
                   (https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise).",
    },
    Bad {
        id: "oorzc.i18n-tools-plus",
        versions: Some(&["1.6.8"]),
        incident: "GlassWorm loader in Open VSX, January 2026 \
                   (https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise).",
    },
    Bad {
        id: "oorzc.mind-map",
        versions: Some(&["1.0.61"]),
        incident: "GlassWorm loader in Open VSX, January 2026 \
                   (https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise).",
    },
    Bad {
        id: "oorzc.scss-to-css-compile",
        versions: Some(&["1.3.4"]),
        incident: "GlassWorm loader in Open VSX, January 2026 \
                   (https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise).",
    },
];

/// Files the Nx Console payload drops on macOS (StepSecurity, May 2026).
const NX_INDICATORS: &[&str] = &[
    "Library/LaunchAgents/com.user.kitty-monitor.plist",
    ".local/share/kitty/cat.py",
];

/// Returns (lowercase id, version) from package.json, or from a folder name such as
/// `publisher.name-1.2.3` or `publisher.name-1.2.3-darwin-arm64`.
fn identify(dir: &Path) -> Option<(String, String)> {
    if let Ok(text) = std::fs::read_to_string(dir.join("package.json")) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let (Some(p), Some(n), Some(ver)) = (
                v["publisher"].as_str(),
                v["name"].as_str(),
                v["version"].as_str(),
            ) {
                return Some((format!("{p}.{n}").to_lowercase(), ver.to_string()));
            }
        }
    }
    // Folder fallback: the version is the right-most `-<digits>.<...>` segment, and a
    // platform suffix (`-darwin-arm64`) may follow it. No version segment: version "".
    let folder = dir.file_name()?.to_string_lossy().to_lowercase();
    let parts: Vec<&str> = folder.split('-').collect();
    // A version segment is dot-separated numbers, e.g. 1.0 or 18.95.0 (not "2.5d").
    let is_version = |seg: &str| {
        seg.contains('.')
            && seg
                .split('.')
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    match (1..parts.len()).rev().find(|&k| is_version(parts[k])) {
        Some(k) => Some((parts[..k].join("-"), parts[k].to_string())),
        None => Some((folder.clone(), String::new())),
    }
}

fn check_extension(
    id: &str,
    version: &str,
    dir: &Path,
    editor: &str,
    scope: &str,
) -> Option<Finding> {
    let bad = BAD_EXTENSIONS.iter().find(|b| b.id == id)?;
    if let Some(vs) = bad.versions {
        if !vs.contains(&version) {
            return None;
        }
    }
    Some(
        Finding::new(
            "extension-known-compromised",
            format!("Known-compromised extension installed in {editor}: {id} {version}"),
            Category::Security,
            Severity::Critical,
            format!("{id} {version} matches a published compromise. {}", bad.incident),
        )
        .with_sub_category(EXT_SUB_CATEGORY)
        .with_scope(scope)
        .with_location(dir.to_string_lossy().as_ref(), None)
        .with_remediation(
            "Uninstall the extension, then follow the incident report: treat the machine as exposed and \
             rotate GitHub, cloud and API tokens that were available to the editor.",
        ),
    )
}

fn safe_relative_location(rel: &str) -> Option<&Path> {
    if rel.is_empty() {
        return None;
    }
    let p = Path::new(rel);
    if p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
    {
        Some(p)
    } else {
        None
    }
}

fn check_extensions_json(
    ext_dir: &Path,
    editor: &str,
    scope: &str,
    compromised_ids: &mut HashSet<String>,
    findings: &mut Vec<Finding>,
) {
    let json_path = ext_dir.join("extensions.json");
    let Ok(text) = std::fs::read_to_string(&json_path) else {
        return;
    };
    let Ok(serde_json::Value::Array(entries)) = serde_json::from_str::<serde_json::Value>(&text)
    else {
        return;
    };

    let mut seen_sideloaded = HashSet::new();
    for entry in entries {
        let Some(raw_id) = entry["identifier"]["id"].as_str() else {
            continue;
        };
        let id = raw_id.trim().to_lowercase();
        if id.is_empty() {
            continue;
        }
        let version = entry["version"].as_str().unwrap_or("").trim();
        let loc_path = entry["relativeLocation"]
            .as_str()
            .and_then(safe_relative_location)
            .map(|rel| ext_dir.join(rel))
            .or_else(|| {
                entry["location"]["path"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| json_path.clone());

        if !compromised_ids.contains(&id) {
            if let Some(f) = check_extension(&id, version, &loc_path, editor, scope) {
                compromised_ids.insert(id.clone());
                findings.push(f);
                continue;
            }
        }

        let Some(source) = entry["metadata"]["source"].as_str() else {
            continue;
        };
        if !(source.eq_ignore_ascii_case("vsix") || source.eq_ignore_ascii_case("resource")) {
            continue;
        }
        if compromised_ids.contains(&id) || !seen_sideloaded.insert(id.clone()) {
            continue;
        }

        let ver_suffix = if version.is_empty() {
            String::new()
        } else {
            format!(" {version}")
        };
        findings.push(
            Finding::new(
                "extension-sideloaded",
                format!("Sideloaded extension installed in {editor}: {id}{ver_suffix}"),
                Category::Security,
                Severity::Medium,
                format!(
                    "{id}{ver_suffix} was installed from a local package (metadata.source = \"{source}\") \
                     rather than the {editor} marketplace gallery. Sideloaded extensions bypass marketplace \
                     malware checks and automatic revocation."
                ),
            )
            .with_sub_category(EXT_SUB_CATEGORY)
            .with_scope(scope)
            .with_location(loc_path.to_string_lossy().as_ref(), None)
            .with_remediation(
                "Verify the provenance of the .vsix file. If you did not build or audit it yourself, \
                 uninstall the extension and install it from the official marketplace instead.",
            ),
        );
    }
}

pub fn scan_extensions(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    scan_extensions_with_home(ctx, home.as_deref())
}

pub fn scan_extensions_with_home(
    ctx: &ScanContext,
    home: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let skip = |reason| {
        (
            Vec::new(),
            vec![Inspection::skipped(
                Category::Security,
                Some(EXT_SUB_CATEGORY),
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

    let mut findings = Vec::new();
    let mut inspections = Vec::new();
    for (dir, editor) in EDITOR_DIRS {
        let ext_dir = home.join(dir).join("extensions");
        let Ok(entries) = std::fs::read_dir(&ext_dir) else {
            continue;
        };
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        // Findings carry the inspection's scope so the report files them under this editor.
        let scope = format!("{editor} ({} extensions)", dirs.len());
        let mut compromised_ids = HashSet::new();
        for d in &dirs {
            if let Some((id, version)) = identify(d) {
                if let Some(f) = check_extension(&id, &version, d, editor, &scope) {
                    compromised_ids.insert(id);
                    findings.push(f);
                }
            }
        }
        check_extensions_json(
            &ext_dir,
            editor,
            &scope,
            &mut compromised_ids,
            &mut findings,
        );
        inspections.push(Inspection::inspected(
            Category::Security,
            Some(EXT_SUB_CATEGORY),
            scope,
        ));
    }

    if inspections.is_empty() {
        inspections.push(Inspection::inspected(
            Category::Security,
            Some(EXT_SUB_CATEGORY),
            "user (no VS Code-family editors found)",
        ));
    }

    const MALWARE_SCOPE: &str = "user (Nx Console backdoor files)";
    inspections.push(Inspection::inspected(
        Category::Security,
        Some(MALWARE_FILES_SUB_CATEGORY),
        MALWARE_SCOPE,
    ));
    for rel in NX_INDICATORS {
        let p = home.join(rel);
        if p.is_file() {
            findings.push(
                Finding::new(
                    "nx-console-backdoor-indicator",
                    "File matching the Nx Console backdoor found",
                    Category::Security,
                    Severity::Critical,
                    "This path matches a published indicator of the May 2026 Nx Console compromise \
                     (https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised).",
                )
                .with_sub_category(MALWARE_FILES_SUB_CATEGORY)
                .with_scope(MALWARE_SCOPE)
                .with_location(p.to_string_lossy().as_ref(), None)
                .with_remediation(
                    "Unload and delete the LaunchAgent and ~/.local/share/kitty/cat.py, then rotate your \
                     GitHub token and any cloud or API keys on this machine. Follow GHSA-c9j4-9m59-847w.",
                ),
            );
        }
    }

    (findings, inspections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Category, InspectionStatus, Severity};
    use std::fs;
    use std::path::PathBuf;

    fn tmp() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("ext_{}_{n}_{nanos}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// Installs a fake extension with a package.json, like VS Code does.
    fn install(
        home: &Path,
        editor_dir: &str,
        folder: &str,
        publisher: &str,
        name: &str,
        version: &str,
    ) {
        let dir = home.join(editor_dir).join("extensions").join(folder);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("package.json"),
            format!(r#"{{"publisher":"{publisher}","name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
    }

    fn scan(home: &Path) -> (Vec<Finding>, Vec<Inspection>) {
        scan_extensions_with_home(&ScanContext::new(), Some(home))
    }

    #[test]
    fn test_extension_nx_console_compromised_version_is_critical() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "nrwl.angular-console-18.95.0",
            "nrwl",
            "angular-console",
            "18.95.0",
        );
        let (f, _) = scan(&home);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].category, Category::Security);
        assert!(f[0].title.contains("nrwl.angular-console"));
        assert!(f[0].description.contains("GHSA-c9j4-9m59-847w"));
    }

    #[test]
    fn test_extension_nx_console_fixed_and_older_versions_not_flagged() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "nrwl.angular-console-18.100.0",
            "nrwl",
            "angular-console",
            "18.100.0",
        );
        install(
            &home,
            ".cursor",
            "nrwl.angular-console-18.94.0",
            "nrwl",
            "angular-console",
            "18.94.0",
        );
        let (f, i) = scan(&home);
        assert!(f.is_empty(), "{f:?}");
        let editors = i
            .iter()
            .filter(|x| x.sub_category.as_deref() == Some(EXT_SUB_CATEGORY))
            .count();
        assert_eq!(editors, 2, "one inspection per editor: {i:?}");
    }

    #[test]
    fn test_extension_glassworm_versions_flagged_in_cursor_and_windsurf() {
        let home = tmp();
        install(
            &home,
            ".cursor",
            "oorzc.mind-map-1.0.61",
            "oorzc",
            "mind-map",
            "1.0.61",
        );
        install(
            &home,
            ".windsurf",
            "oorzc.i18n-tools-plus-1.6.8-universal",
            "oorzc",
            "i18n-tools-plus",
            "1.6.8",
        );
        install(
            &home,
            ".cursor",
            "oorzc.scss-to-css-compile-1.3.3",
            "oorzc",
            "scss-to-css-compile",
            "1.3.3",
        );
        let (f, _) = scan(&home);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|x| x.severity == Severity::Critical));
    }

    #[test]
    fn test_extension_ssh_tools_any_version_flagged() {
        let home = tmp();
        install(
            &home,
            ".vscode-oss",
            "oorzc.ssh-tools-0.4.0",
            "oorzc",
            "ssh-tools",
            "0.4.0",
        );
        let (f, _) = scan(&home);
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn test_extension_ids_match_case_insensitively_and_without_package_json() {
        let home = tmp();
        // No package.json: fall back to the folder name, including a platform suffix.
        fs::create_dir_all(
            home.join(".vscode/extensions/NRWL.Angular-Console-18.95.0-darwin-arm64"),
        )
        .unwrap();
        let (f, _) = scan(&home);
        assert_eq!(f.len(), 1, "{f:?}");
    }

    #[test]
    fn test_extension_nx_backdoor_indicators_are_critical() {
        let home = tmp();
        fs::create_dir_all(home.join("Library/LaunchAgents")).unwrap();
        fs::write(
            home.join("Library/LaunchAgents/com.user.kitty-monitor.plist"),
            "<plist/>",
        )
        .unwrap();
        fs::create_dir_all(home.join(".local/share/kitty")).unwrap();
        fs::write(home.join(".local/share/kitty/cat.py"), "print(1)").unwrap();
        let (f, _) = scan(&home);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|x| x.severity == Severity::Critical));
        assert!(f
            .iter()
            .all(|x| x.remediation.as_deref().unwrap_or("").contains("token")));
    }

    #[test]
    fn test_extension_normal_setup_has_zero_findings() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "ms-python.python-2026.2.0-darwin-arm64",
            "ms-python",
            "python",
            "2026.2.0",
        );
        install(
            &home,
            ".vscode",
            "esbenp.prettier-vscode-11.0.0",
            "esbenp",
            "prettier-vscode",
            "11.0.0",
        );
        fs::create_dir_all(home.join(".config/kitty")).unwrap();
        fs::write(home.join(".config/kitty/kitty.conf"), "font_size 12").unwrap();
        let (f, i) = scan(&home);
        assert!(f.is_empty(), "{f:?}");
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Inspected { .. })));
    }

    #[test]
    fn test_extension_findings_render_under_their_sub_category() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "nrwl.angular-console-18.95.0",
            "nrwl",
            "angular-console",
            "18.95.0",
        );
        fs::create_dir_all(home.join("Library/LaunchAgents")).unwrap();
        fs::write(
            home.join("Library/LaunchAgents/com.user.kitty-monitor.plist"),
            "x",
        )
        .unwrap();
        let (f, i) = scan(&home);
        let r = crate::render_report(&crate::ScanResult::new(f, i, "2026-10-25T00:00:00Z"));
        assert!(!r.contains("Other findings"), "{r}");
        assert!(!r.contains("scope unknown"), "{r}");
    }

    fn render(f: Vec<Finding>, i: Vec<Inspection>) -> String {
        crate::render_report(&crate::ScanResult::new(f, i, "2026-10-25T00:00:00Z"))
    }

    #[test]
    fn test_extension_findings_render_with_several_editors() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "nrwl.angular-console-18.95.0",
            "nrwl",
            "angular-console",
            "18.95.0",
        );
        install(
            &home,
            ".cursor",
            "esbenp.prettier-vscode-11.0.0",
            "esbenp",
            "prettier-vscode",
            "11.0.0",
        );
        install(
            &home,
            ".windsurf",
            "oorzc.mind-map-1.0.61",
            "oorzc",
            "mind-map",
            "1.0.61",
        );
        let (f, i) = scan(&home);
        let r = render(f, i);
        assert!(!r.contains("scope unknown"), "{r}");
        assert!(!r.contains("Other findings"), "{r}");
        assert!(
            r.contains("Cursor"),
            "every editor inspection is still listed: {r}"
        );
    }

    #[test]
    fn test_extension_backdoor_files_are_not_attributed_to_an_editor() {
        let home = tmp();
        fs::create_dir_all(home.join("Library/LaunchAgents")).unwrap();
        fs::write(
            home.join("Library/LaunchAgents/com.user.kitty-monitor.plist"),
            "x",
        )
        .unwrap();
        let (f, i) = scan(&home);
        assert_eq!(
            f[0].sub_category.as_deref(),
            Some(MALWARE_FILES_SUB_CATEGORY)
        );
        let r = render(f, i);
        assert!(!r.contains("scope unknown"), "{r}");
        assert!(!r.contains("Other findings"), "{r}");
    }

    #[test]
    fn test_extension_folder_names_with_digits_in_the_name_parse_from_the_right() {
        let d = tmp();
        for (folder, id, ver) in [
            (
                "company.app-3d-viewer-1.0.0",
                "company.app-3d-viewer",
                "1.0.0",
            ),
            (
                "pub.tool-2-extension-1.0.0-darwin-arm64",
                "pub.tool-2-extension",
                "1.0.0",
            ),
            ("oorzc.ssh-tools", "oorzc.ssh-tools", ""),
            ("pub.render-2.5d", "pub.render-2.5d", ""),
            ("pub.render-2.5d-1.4.0", "pub.render-2.5d", "1.4.0"),
        ] {
            let p = d.join(folder);
            fs::create_dir_all(&p).unwrap();
            assert_eq!(
                identify(&p),
                Some((id.to_string(), ver.to_string())),
                "{folder}"
            );
        }
    }

    #[test]
    fn test_extension_unversioned_folder_of_an_all_versions_entry_is_flagged() {
        let home = tmp();
        fs::create_dir_all(home.join(".vscode/extensions/oorzc.ssh-tools")).unwrap();
        let (f, _) = scan(&home);
        assert_eq!(f.len(), 1, "{f:?}");
    }

    #[test]
    fn test_extension_no_editors_is_one_honest_inspection() {
        let home = tmp();
        let (f, i) = scan(&home);
        assert!(f.is_empty());
        let editors: Vec<_> = i
            .iter()
            .filter(|x| x.sub_category.as_deref() == Some(EXT_SUB_CATEGORY))
            .collect();
        assert_eq!(editors.len(), 1);
        assert!(i
            .iter()
            .all(|x| matches!(x.status, InspectionStatus::Inspected { .. })));
    }

    #[test]
    fn test_extension_sideloaded_vsix_is_flagged_medium_and_renders_cleanly() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "acme.internal-helper-1.2.3",
            "acme",
            "internal-helper",
            "1.2.3",
        );
        let ext_json = r#"[
            {
                "identifier": { "id": "Acme.Internal-Helper", "uuid": "1111" },
                "version": "1.2.3",
                "relativeLocation": "acme.internal-helper-1.2.3",
                "metadata": {
                    "installedTimestamp": 1753577227722,
                    "source": "vsix"
                }
            }
        ]"#;
        fs::write(home.join(".vscode/extensions/extensions.json"), ext_json).unwrap();

        let (f, i) = scan(&home);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].id, "extension-sideloaded");
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].category, Category::Security);
        assert_eq!(f[0].sub_category.as_deref(), Some(EXT_SUB_CATEGORY));
        assert!(f[0]
            .title
            .contains("Sideloaded extension installed in VS Code: acme.internal-helper 1.2.3"));
        assert!(f[0].description.contains("metadata.source = \"vsix\""));
        assert!(f[0]
            .file_path
            .as_deref()
            .unwrap_or("")
            .ends_with("acme.internal-helper-1.2.3"));

        let r = render(f, i);
        assert!(!r.contains("scope unknown"), "{r}");
        assert!(!r.contains("Other findings"), "{r}");
    }

    #[test]
    fn test_extension_sideloaded_resource_is_flagged_medium() {
        let home = tmp();
        let ext_dir = home.join(".cursor/extensions");
        fs::create_dir_all(&ext_dir).unwrap();
        let loc = ext_dir.join("local.dev-ext-0.1.0");
        let ext_json = serde_json::json!([
            {
                "identifier": { "id": "local.dev-ext" },
                "version": "0.1.0",
                "location": { "$mid": 1, "path": loc.to_string_lossy(), "scheme": "file" },
                "metadata": {
                    "source": "resource"
                }
            }
        ]);
        fs::write(ext_dir.join("extensions.json"), ext_json.to_string()).unwrap();

        let (f, i) = scan(&home);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].id, "extension-sideloaded");
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0]
            .title
            .contains("Sideloaded extension installed in Cursor: local.dev-ext 0.1.0"));
        assert!(f[0].description.contains("metadata.source = \"resource\""));
        assert_eq!(
            f[0].file_path.as_deref(),
            Some(loc.to_string_lossy().as_ref())
        );

        let r = render(f, i);
        assert!(!r.contains("scope unknown"), "{r}");
        assert!(!r.contains("Other findings"), "{r}");
    }

    #[test]
    fn test_extension_gallery_and_missing_source_not_flagged() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "ms-azuretools.vscode-docker-2.0.0",
            "ms-azuretools",
            "vscode-docker",
            "2.0.0",
        );
        let ext_json = r#"[
            {
                "identifier": { "id": "ms-azuretools.vscode-docker" },
                "version": "2.0.0",
                "relativeLocation": "ms-azuretools.vscode-docker-2.0.0",
                "metadata": {
                    "source": "gallery"
                }
            },
            {
                "identifier": { "id": "ms-python.python" },
                "version": "2026.2.0",
                "metadata": {}
            },
            {
                "identifier": { "id": "esbenp.prettier-vscode" },
                "version": "11.0.0"
            }
        ]"#;
        fs::write(home.join(".vscode/extensions/extensions.json"), ext_json).unwrap();

        let (f, _) = scan(&home);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn test_extension_malformed_extensions_json_does_not_break_compromised_folder_scan() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "nrwl.angular-console-18.95.0",
            "nrwl",
            "angular-console",
            "18.95.0",
        );
        fs::write(
            home.join(".vscode/extensions/extensions.json"),
            "{not valid json",
        )
        .unwrap();

        let (f, _) = scan(&home);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].id, "extension-known-compromised");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn test_extension_deduplicates_sideloaded_and_prioritizes_compromised() {
        let home = tmp();
        install(
            &home,
            ".vscode",
            "nrwl.angular-console-18.95.0",
            "nrwl",
            "angular-console",
            "18.95.0",
        );
        let ext_json = r#"[
            {
                "identifier": { "id": "nrwl.angular-console" },
                "version": "18.95.0",
                "relativeLocation": "nrwl.angular-console-18.95.0",
                "metadata": { "source": "vsix" }
            },
            {
                "identifier": { "id": "acme.dup-ext" },
                "version": "1.0.0",
                "relativeLocation": "../escape",
                "metadata": { "source": "VSIX" }
            },
            {
                "identifier": { "id": "acme.dup-ext" },
                "version": "1.0.1",
                "metadata": { "source": "vsix" }
            }
        ]"#;
        fs::write(home.join(".vscode/extensions/extensions.json"), ext_json).unwrap();

        let (f, _) = scan(&home);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!(f[0].id, "extension-known-compromised");
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[1].id, "extension-sideloaded");
        assert_eq!(f[1].severity, Severity::Medium);
        assert!(f[1]
            .file_path
            .as_deref()
            .unwrap_or("")
            .ends_with("extensions.json"));
    }
}
