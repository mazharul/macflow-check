use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, ScanContext, Severity};
use serde_json::Value;

pub const TASKS_SUB_CATEGORY: &str = "VS Code tasks";
pub const KEYS_SUB_CATEGORY: &str = "Plaintext AI keys";
const DEFAULT_DEV_ROOTS: [&str; 4] = ["code", "projects", "dev", "src"];
const TASK_REMEDIATION: &str = "Remove \"runOn\": \"folderOpen\" from runOptions or disable automatic task execution (task.allowAutomaticTasks) in VS Code/Cursor.";
const PUBLIC_GOOGLE_KEY_REMEDIATION: &str = "Restrict this key in Google Cloud Console > APIs & Services > Credentials: limit it to the APIs the app uses (for example Firebase or Maps, not the Generative Language API) and to your app's HTTP referrers or bundle IDs.";
const KEY_REMEDIATION: &str = "Remove plaintext API key from file and load credentials dynamically via a secret manager or keychain.";
const MAX_SEARCH_DEPTH: usize = 4;
const IGNORED_DIR_NAMES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
];

pub fn scan_vscode_tasks(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    scan_vscode_tasks_with_home(ctx, None)
}

pub fn scan_vscode_tasks_with_home(
    ctx: &ScanContext,
    home_override: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let user_rels = [
        "Library/Application Support/Code/User/tasks.json",
        "Library/Application Support/Cursor/User/tasks.json",
        ".vscode/tasks.json",
    ];
    let meta = (
        TASKS_SUB_CATEGORY,
        "user (no user tasks.json present)",
        "0 tasks.json files found, not present",
    );
    scan_locations(
        ctx,
        home_override,
        meta,
        &user_rels,
        |d| {
            let p = d.join(".vscode/tasks.json");
            p.is_file().then_some(p).into_iter().collect()
        },
        inspect_tasks_file,
    )
}

pub fn inspect_tasks_file(path: &Path, scope: &str) -> (Vec<Finding>, Inspection) {
    read_and_inspect(path, scope, TASKS_SUB_CATEGORY, inspect_tasks_content)
}

pub fn inspect_tasks_content(
    content: &str,
    display_path: &str,
    scope: &str,
) -> (Vec<Finding>, Inspection) {
    let val: Value = match serde_json::from_str(&strip_jsonc(content)) {
        Ok(v) => v,
        Err(e) => {
            return (
                Vec::new(),
                Inspection::unparseable(
                    Category::AgentAudit,
                    Some(TASKS_SUB_CATEGORY),
                    Some(display_path),
                    e.to_string(),
                ),
            );
        }
    };

    let (mut findings, mut search_from) = (Vec::new(), 1);
    for task in val["tasks"].as_array().into_iter().flatten() {
        let label = task["label"]
            .as_str()
            .or_else(|| task["taskName"].as_str())
            .unwrap_or("unnamed");
        let task_line = find_task_line(content, label, search_from);
        if let Some(l) = task_line {
            search_from = l + 1;
        }
        if task["runOptions"]["runOn"].as_str() != Some("folderOpen") {
            continue;
        }
        let sev = if is_critical_task_payload(&extract_task_command_text(task)) {
            Severity::Critical
        } else {
            Severity::High
        };
        let line = task_line
            .or_else(|| find_line_from(content, "\"folderOpen\"", search_from))
            .or(Some(1));
        findings.push(
            Finding::new(
                "vscode-task-folder-open",
                format!("Automatic folderOpen task '{label}'"),
                Category::AgentAudit,
                sev,
                format!("Task '{label}' configures runOptions.runOn = \"folderOpen\", executing automatically when the workspace opens (Contagious Interview / Keyv folderOpen attack vector)."),
            )
            .with_sub_category(TASKS_SUB_CATEGORY)
            .with_scope(scope)
            .with_location(display_path, line)
            .with_remediation(TASK_REMEDIATION),
        );
    }
    (
        findings,
        Inspection::inspected(Category::AgentAudit, Some(TASKS_SUB_CATEGORY), scope),
    )
}

fn extract_task_command_text(task: &Value) -> String {
    let mut parts = Vec::new();
    let push_args = |arr: Option<&Vec<Value>>, out: &mut Vec<String>| {
        for s in arr
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().or_else(|| x["value"].as_str()))
        {
            out.push(s.to_string());
        }
    };
    for v in ["command", "osx", "linux", "windows"]
        .iter()
        .filter_map(|k| task.get(*k))
    {
        if let Some(s) = v.as_str().or_else(|| v["command"].as_str()) {
            parts.push(s.to_string());
        }
        push_args(v["args"].as_array(), &mut parts);
    }
    push_args(task["args"].as_array(), &mut parts);
    parts.join(" ")
}

fn is_critical_task_payload(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    let toks: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .filter(|s| !s.is_empty())
        .collect();
    let has_sh = toks
        .iter()
        .any(|t| matches!(*t, "sh" | "bash" | "zsh" | "python" | "python3"));
    let has_c = toks
        .iter()
        .any(|t| *t == "-c" || (t.starts_with('-') && !t.starts_with("--") && t.ends_with('c')));
    lower.contains("/dev/tcp")
        || (has_sh && has_c)
        || (toks.contains(&"node") && (toks.contains(&"-e") || toks.contains(&"--eval")))
        || toks
            .iter()
            .any(|t| matches!(*t, "curl" | "wget" | "base64" | "eval" | "nc" | "ncat"))
}

pub fn scan_plaintext_keys(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    scan_plaintext_keys_with_home(ctx, None)
}

pub fn scan_plaintext_keys_with_home(
    ctx: &ScanContext,
    home_override: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let user_rels = [
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".config/fish/config.fish",
        ".env",
    ];
    let meta = (
        KEYS_SUB_CATEGORY,
        "user (no shell startup or ~/.env files present)",
        "0 .env files found, not present",
    );
    scan_locations(
        ctx,
        home_override,
        meta,
        &user_rels,
        collect_env_files,
        inspect_env_file,
    )
}

pub fn inspect_env_file(path: &Path, scope: &str) -> (Vec<Finding>, Inspection) {
    read_and_inspect(path, scope, KEYS_SUB_CATEGORY, inspect_env_content)
}

pub fn inspect_env_content(
    content: &str,
    display_path: &str,
    scope: &str,
) -> (Vec<Finding>, Inspection) {
    let mut findings = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let Some((var_name, raw_val)) = parse_env_assignment(raw_line) else {
            continue;
        };
        let val = strip_inline_comment_and_quotes(raw_val);
        if is_placeholder_or_dynamic(&val) {
            continue;
        }
        let Some((provider, pfx)) = classify_ai_key(&var_name, &val) else {
            continue;
        };
        let public_var = is_public_client_var(&var_name);
        let finding = if pfx == "AIza..."
            && !is_ai_key_var(&var_name)
            && (public_var || is_google_web_key_var(&var_name))
        {
            Finding::new(
                format!("public-google-key:{var_name}"),
                format!("Client-side Google API key in {var_name} ({pfx})"),
                Category::AgentAudit,
                Severity::Low,
                format!("Variable '{var_name}' holds a Google API key ({pfx}) at line {line_no}. Firebase and Maps web keys ship to browsers by design, but an unrestricted key also works for Gemini and other billed APIs."),
            )
            .with_remediation(PUBLIC_GOOGLE_KEY_REMEDIATION)
        } else {
            let exposure = if public_var {
                " Variables with this prefix are bundled into client JavaScript, so this key reaches every browser that loads the app."
            } else {
                ""
            };
            Finding::new(
                format!("plaintext-ai-key:{var_name}"),
                format!("Plaintext {provider} API key in {var_name} ({pfx})"),
                Category::AgentAudit,
                Severity::High,
                format!("Variable '{var_name}' assigns a plaintext {provider} credential ({pfx}) at line {line_no}.{exposure}"),
            )
            .with_remediation(KEY_REMEDIATION)
        };
        findings.push(
            finding
                .with_sub_category(KEYS_SUB_CATEGORY)
                .with_scope(scope)
                .with_location(display_path, Some(line_no)),
        );
    }
    (
        findings,
        Inspection::inspected(Category::AgentAudit, Some(KEYS_SUB_CATEGORY), scope),
    )
}

fn parse_env_assignment(line: &str) -> Option<(String, &str)> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    if let Some(rest) = t
        .strip_prefix("set")
        .filter(|r| r.starts_with(char::is_whitespace))
    {
        let mut rem = rest.trim_start();
        while rem.starts_with('-') {
            let end = rem.find(char::is_whitespace)?;
            rem = rem[end..].trim_start();
        }
        let end = rem.find(char::is_whitespace)?;
        let var = &rem[..end];
        if is_valid_env_ident(var) {
            return Some((var.to_string(), rem[end..].trim()));
        }
    }
    let body = t
        .strip_prefix("export")
        .filter(|r| r.starts_with(char::is_whitespace))
        .map_or(t, str::trim);
    let (k, v) = body.split_once('=')?;
    is_valid_env_ident(k.trim()).then(|| (k.trim().to_string(), v.trim()))
}

fn is_valid_env_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().unwrap().is_ascii_digit()
}

fn strip_inline_comment_and_quotes(raw: &str) -> String {
    let s = raw.trim();
    if let Some(q) = s.chars().next().filter(|&c| c == '"' || c == '\'') {
        let mut esc = false;
        for (i, c) in s[1..].char_indices() {
            if !esc && c == q {
                return s[1..=i].trim().to_string();
            }
            esc = !esc && c == '\\' && q == '"';
        }
    }
    let u = s
        .char_indices()
        .find(|&(i, c)| c == '#' && (i == 0 || s[..i].ends_with(char::is_whitespace)))
        .map_or(s, |(i, _)| &s[..i]);
    u.trim()
        .trim_end_matches([';', '"', '\'', ' ', '\t'])
        .trim_start_matches(['"', '\''])
        .trim()
        .to_string()
}

fn is_placeholder_or_dynamic(val: &str) -> bool {
    let lower = val.to_ascii_lowercase();
    val.len() < 12
        || val.starts_with(['$', '`'])
        || val.contains("${")
        || val.contains("$(")
        || (val.starts_with('<') && val.ends_with('>'))
        || "/ ~/ ./ ../ http:// https:// op://"
            .split_whitespace()
            .any(|p| val.starts_with(p))
        || "your-api-key|your_api_key|your-key|your_key|replace_me|changeme|change_me|todo|example|placeholder|insert_|op read|security find-generic-password"
            .split('|')
            .any(|p| lower.contains(p))
        || lower.trim_start_matches("sk-").chars().all(|c| c == 'x' || c == '*')
}

/// Frontend build tools inline variables with these prefixes into client code.
fn is_public_client_var(var_name: &str) -> bool {
    let up = var_name.to_ascii_uppercase();
    [
        "NEXT_PUBLIC_",
        "VITE_",
        "REACT_APP_",
        "EXPO_PUBLIC_",
        "NUXT_PUBLIC_",
        "GATSBY_",
        "PUBLIC_",
        "VUE_APP_",
    ]
    .iter()
    .any(|p| up.starts_with(p))
}

/// Firebase and Maps keys are web keys even without a public prefix.
fn is_google_web_key_var(var_name: &str) -> bool {
    let up = var_name.to_ascii_uppercase();
    up.contains("FIREBASE") || up.contains("MAPS") || up.contains("GOOGLE_MAP")
}

/// Names that say the key is for Gemini, whatever its prefix: never a web key.
fn is_ai_key_var(var_name: &str) -> bool {
    let up = var_name.to_ascii_uppercase();
    ["GEMINI", "GENERATIVE", "GENAI", "VERTEX"]
        .iter()
        .any(|w| up.contains(w))
}

fn classify_ai_key(var_name: &str, val: &str) -> Option<(&'static str, &'static str)> {
    for (pfx, prov, red) in [
        ("sk-ant-", "Anthropic", "sk-ant-..."),
        ("sk-or-v1-", "OpenRouter", "sk-or-v1-..."),
        ("sk-proj-", "OpenAI", "sk-proj-..."),
        ("gsk_", "Groq", "gsk_..."),
        ("hf_", "HuggingFace", "hf_..."),
        ("AIza", "Google AI", "AIza..."),
        ("sk-", "OpenAI", "sk-..."),
    ] {
        if val.starts_with(pfx) {
            return Some((prov, red));
        }
    }
    match var_name.to_ascii_uppercase().as_str() {
        "ANTHROPIC_API_KEY" => Some(("Anthropic", "REDACTED...")),
        "OPENAI_API_KEY" => Some(("OpenAI", "REDACTED...")),
        "GEMINI_API_KEY" | "GOOGLE_API_KEY" | "GOOGLE_GENERATIVE_AI_API_KEY" => {
            Some(("Google AI", "REDACTED..."))
        }
        "OPENROUTER_API_KEY" => Some(("OpenRouter", "REDACTED...")),
        "GROQ_API_KEY" => Some(("Groq", "REDACTED...")),
        "HF_TOKEN" | "HUGGINGFACE_API_KEY" | "HUGGING_FACE_HUB_TOKEN" => {
            Some(("HuggingFace", "REDACTED..."))
        }
        _ => None,
    }
}

fn collect_env_files(dir: &Path) -> Vec<PathBuf> {
    let skip = ".env.example .env.sample .env.template .env.dist .env.test";
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.file_name().and_then(|n| n.to_str()).is_some_and(|nm| {
                    (nm == ".env" || nm.starts_with(".env."))
                        && !skip.split_whitespace().any(|s| s == nm)
                })
        })
        .collect();
    files.sort();
    files
}

fn scan_locations<F, I>(
    ctx: &ScanContext,
    home_override: Option<&Path>,
    (sub, empty_user_msg, empty_proj_msg): (&str, &str, &str),
    user_rels: &[&str],
    find_proj_files: F,
    inspect_fn: I,
) -> (Vec<Finding>, Vec<Inspection>)
where
    F: Fn(&Path) -> Vec<PathBuf>,
    I: Fn(&Path, &str) -> (Vec<Finding>, Inspection),
{
    let (mut findings, mut inspections) = (Vec::new(), Vec::new());
    if !ctx.is_category_selected(Category::AgentAudit) {
        inspections.push(Inspection::skipped(
            Category::AgentAudit,
            Some(sub),
            Some("category not selected"),
        ));
        return (findings, inspections);
    }

    let home_dir = home_override
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("MACFLOW_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from));

    if let Some(ref home) = home_dir {
        let mut found_user = false;
        for r in user_rels {
            let p = home.join(r);
            if p.is_file() {
                found_user = true;
                let (f, insp) = inspect_fn(&p, "user");
                findings.extend(f);
                inspections.push(insp);
            }
        }
        if !found_user {
            inspections.push(Inspection::inspected(
                Category::AgentAudit,
                Some(sub),
                empty_user_msg,
            ));
        }
    } else {
        inspections.push(Inspection::skipped(
            Category::AgentAudit,
            Some(sub),
            Some("home directory unavailable"),
        ));
    }

    let roots = if !ctx.root_paths.is_empty() {
        ctx.root_paths.clone()
    } else if let Some(ref home) = home_dir {
        let ex: Vec<PathBuf> = DEFAULT_DEV_ROOTS
            .iter()
            .map(|r| home.join(r))
            .filter(|p| p.is_dir())
            .collect();
        if ex.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            ex
        }
    } else {
        vec![PathBuf::from(".")]
    };

    let cur_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for root in roots {
        let dirs = collect_search_dirs(&root, MAX_SEARCH_DEPTH);
        let cands: Vec<PathBuf> = dirs.iter().flat_map(|d| find_proj_files(d)).collect();
        if cands.is_empty() {
            let label = compute_root_scope_label(&root, home_dir.as_deref(), &cur_dir);
            inspections.push(Inspection::inspected(
                Category::AgentAudit,
                Some(sub),
                format!("proj:{label} ({empty_proj_msg})"),
            ));
        }
        for c in cands {
            let rel = compute_relative_scope_path(&c, &root, home_dir.as_deref(), &cur_dir);
            let (f, insp) = inspect_fn(&c, &format!("proj:{rel}"));
            findings.extend(f);
            inspections.push(insp);
        }
    }
    (findings, inspections)
}

/// Project folders to search: the --root paths, else ~/code, ~/projects, ~/dev, ~/src.
pub(crate) fn project_dirs(ctx: &ScanContext) -> Vec<PathBuf> {
    let home = std::env::var_os("MACFLOW_HOME")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    let roots: Vec<PathBuf> = if !ctx.root_paths.is_empty() {
        ctx.root_paths.clone()
    } else {
        home.iter()
            .flat_map(|h| DEFAULT_DEV_ROOTS.iter().map(move |r| h.join(r)))
            .filter(|p| p.is_dir())
            .collect()
    };
    roots
        .iter()
        .flat_map(|r| collect_search_dirs(r, MAX_SEARCH_DEPTH))
        .collect()
}

fn is_ignored_dir(name: &str) -> bool {
    name.starts_with('.') || IGNORED_DIR_NAMES.contains(&name)
}

fn collect_search_dirs(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    walk_subdirs(root, 1, max_depth, &mut dirs);
    dirs
}

fn walk_subdirs(current: &Path, depth: usize, max_depth: usize, dirs: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(current) else {
        return;
    };
    let mut subs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_symlink() {
            continue;
        }
        if !p.is_dir() {
            continue;
        }
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if is_ignored_dir(name) {
                continue;
            }
            subs.push(p);
        }
    }
    subs.sort();
    for sub in subs {
        dirs.push(sub.clone());
        walk_subdirs(&sub, depth + 1, max_depth, dirs);
    }
}

fn read_and_inspect(
    path: &Path,
    scope: &str,
    sub: &str,
    f: fn(&str, &str, &str) -> (Vec<Finding>, Inspection),
) -> (Vec<Finding>, Inspection) {
    let d = path.display().to_string();
    std::fs::read_to_string(path).map_or_else(
        |e| {
            (
                Vec::new(),
                Inspection::unparseable(Category::AgentAudit, Some(sub), Some(&d), e.to_string()),
            )
        },
        |c| f(&c, &d, scope),
    )
}

fn compute_relative_scope_path(
    path: &Path,
    root: &Path,
    home: Option<&Path>,
    cur: &Path,
) -> String {
    let parent = root.parent().filter(|p| !p.as_os_str().is_empty());
    for base in [home, Some(cur), parent, Some(root)].into_iter().flatten() {
        if let Ok(rel) = path.strip_prefix(base) {
            return rel.display().to_string();
        }
    }
    let s = path.display().to_string();
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

fn compute_root_scope_label(root: &Path, home: Option<&Path>, cur: &Path) -> String {
    for base in [home, Some(cur)].into_iter().flatten() {
        if let Ok(s) = root.strip_prefix(base).map(|r| r.display().to_string()) {
            if !s.is_empty() {
                return s;
            }
        }
    }
    root.file_name()
        .and_then(|n| n.to_str())
        .filter(|s| !s.is_empty())
        .map_or_else(|| root.display().to_string(), str::to_string)
}

pub(crate) fn strip_jsonc(input: &str) -> String {
    let (mut out, mut chars, mut in_str, mut esc) =
        (String::new(), input.chars().peekable(), false, false);
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            esc = !esc && c == '\\';
            if !esc && c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            out.push(c);
        } else if c == '/' && chars.peek() == Some(&'/') {
            for nc in chars.by_ref() {
                if nc == '\n' {
                    out.push('\n');
                    break;
                }
            }
        } else if c == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(nc) = chars.next() {
                if nc == '\n' {
                    out.push('\n');
                } else if nc == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    let ch: Vec<char> = out.chars().collect();
    let (mut res, mut s_in, mut s_esc) = (String::with_capacity(out.len()), false, false);
    for (i, &c) in ch.iter().enumerate() {
        if s_in {
            res.push(c);
            s_esc = !s_esc && c == '\\';
            if !s_esc && c == '"' {
                s_in = false;
            }
        } else if c == '"' {
            s_in = true;
            res.push(c);
        } else if !(c == ','
            && matches!(
                ch[i + 1..].iter().find(|x| !x.is_whitespace()),
                Some('}' | ']')
            ))
        {
            res.push(c);
        }
    }
    res
}

fn find_task_line(content: &str, label: &str, from_line: usize) -> Option<usize> {
    let q = format!("\"{label}\"");
    find_line_pred(content, from_line, |l| {
        (l.contains("\"label\"") || l.contains("\"taskName\"")) && l.contains(&q)
    })
    .or_else(|| find_line_from(content, &q, from_line))
}

fn find_line_from(content: &str, needle: &str, from_line: usize) -> Option<usize> {
    (!needle.is_empty()).then(|| find_line_pred(content, from_line, |l| l.contains(needle)))?
}

fn find_line_pred(content: &str, from: usize, pred: impl Fn(&str) -> bool) -> Option<usize> {
    content
        .lines()
        .enumerate()
        .skip(from.saturating_sub(1))
        .find(|(_, l)| pred(l))
        .map(|(i, _)| i + 1)
}
