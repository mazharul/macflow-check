use std::path::{Path, PathBuf};

use crate::models::{Category, Finding, Inspection, InspectionStatus, ScanContext, Severity};
use serde_json::Value;

pub const MCP_SUB_CATEGORY: &str = "MCP servers";
const REM_URL: &str =
    "Remove credentials from the URL and provide authentication headers dynamically at runtime.";
const REM_ENV: &str = "Reference credentials via dynamic environment variables or a secret store.";
const REM_ARG: &str =
    "Pass credentials via environment variables rather than command-line arguments.";

pub fn scan_mcp_servers(ctx: &ScanContext) -> (Vec<Finding>, Vec<Inspection>) {
    scan_mcp_servers_with_home(ctx, None)
}

pub fn scan_mcp_servers_with_home(
    ctx: &ScanContext,
    home_override: Option<&Path>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let (mut findings, mut inspections) = (Vec::new(), Vec::new());
    if !ctx.is_category_selected(Category::AgentAudit) {
        inspections.push(Inspection::skipped(
            Category::AgentAudit,
            Some(MCP_SUB_CATEGORY),
            Some("category not selected"),
        ));
        return (findings, inspections);
    }

    let home_dir = home_override
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("MACFLOW_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from));

    if let Some(ref home) = home_dir {
        let cj = home.join(".claude.json");
        if cj.exists() {
            let (f, insp) = inspect_claude_json_file(&cj);
            findings.extend(f);
            inspections.extend(insp);
        } else {
            inspections.push(Inspection::skipped(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                Some("file not present"),
            ));
        }

        // 1. Cursor (`user:cursor`): ~/.cursor/mcp.json
        let cursor_p = home.join(".cursor/mcp.json");
        if cursor_p.exists() {
            let (f, insp) = inspect_mcp_file(&cursor_p, "user:cursor");
            findings.extend(f);
            inspections.push(insp);
        } else {
            inspections.push(Inspection::skipped(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                Some("file not present"),
            ));
        }

        // 2. Windsurf (`user:windsurf`): ~/.codeium/windsurf/mcp_config.json
        let windsurf_p = home.join(".codeium/windsurf/mcp_config.json");
        if windsurf_p.exists() {
            let (f, insp) = inspect_mcp_file(&windsurf_p, "user:windsurf");
            findings.extend(f);
            inspections.push(insp);
        } else {
            inspections.push(Inspection::skipped(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                Some("file not present"),
            ));
        }

        // 3. VS Code / Copilot (`user:vscode`):
        scan_multi_candidate_tool(
            &[
                home.join("Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"),
                home.join("Library/Application Support/Code/User/mcp.json"),
                home.join(".vscode/mcp.json"),
            ],
            Some(&home.join("Library/Application Support/Code/User/settings.json")),
            |v| {
                v.get("mcp.servers").is_some()
                    || v.get("mcpServers").is_some()
                    || v.get("servers").is_some()
                    || v.get("mcp").and_then(|m| m.get("servers")).is_some()
            },
            "user:vscode",
            &mut findings,
            &mut inspections,
        );

        // 4. Antigravity / Gemini (`user:antigravity`):
        scan_multi_candidate_tool(
            &[
                home.join(".gemini/antigravity/mcp.json"),
                home.join(".gemini/antigravity/mcp_config.json"),
            ],
            Some(&home.join(".gemini/settings.json")),
            |v| {
                v.get("mcpServers").is_some()
                    || v.get("mcp.servers").is_some()
                    || v.get("servers").is_some()
            },
            "user:antigravity",
            &mut findings,
            &mut inspections,
        );

        // 5. Codex (`user:codex`): ~/.codex/config.toml
        let codex_p = home.join(".codex/config.toml");
        if codex_p.exists() {
            let (f, insp) = inspect_codex_toml_file(&codex_p, "user:codex");
            findings.extend(f);
            inspections.push(insp);
        } else {
            inspections.push(Inspection::skipped(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                Some("file not present"),
            ));
        }

        let other_targets = [
            (".mcp.json", "user"),
            (
                "Library/Application Support/Claude/claude_desktop_config.json",
                "user (Claude Desktop)",
            ),
        ];
        for (rel, sc) in other_targets {
            let p = home.join(rel);
            if p.exists() {
                let (f_res, insp) = inspect_mcp_file(&p, sc);
                findings.extend(f_res);
                inspections.push(insp);
            }
        }
    } else {
        inspections.push(Inspection::skipped(
            Category::AgentAudit,
            Some(MCP_SUB_CATEGORY),
            Some("home directory unavailable"),
        ));
    }

    let cur_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let roots: Vec<PathBuf> = if !ctx.root_paths.is_empty() {
        ctx.root_paths.clone()
    } else if let Some(ref home) = home_dir {
        ["code", "projects", "dev", "src"]
            .iter()
            .map(|d| home.join(d))
            .filter(|p| p.is_dir())
            .collect()
    } else {
        Vec::new()
    };

    let base = home_dir.as_deref().unwrap_or(&cur_dir);
    for root in &roots {
        let mut dirs = vec![root.clone()];
        if let Ok(entries) = std::fs::read_dir(root) {
            let mut ch: Vec<PathBuf> = entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.is_dir()
                        && !p
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(".")
                            .starts_with('.')
                })
                .collect();
            ch.sort();
            dirs.extend(ch);
        }
        for dir in dirs {
            for rel in [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"] {
                let t = dir.join(rel);
                if t.exists() {
                    let sc = format!("proj:{}/{rel}", compute_relative_scope_path(&dir, base));
                    let (f, insp) = inspect_mcp_file(&t, &sc);
                    findings.extend(f);
                    inspections.push(insp);
                }
            }
        }
    }
    (findings, inspections)
}

fn scan_multi_candidate_tool(
    candidates: &[PathBuf],
    settings_path: Option<&Path>,
    has_mcp_config: impl Fn(&Value) -> bool,
    scope: &str,
    findings: &mut Vec<Finding>,
    inspections: &mut Vec<Inspection>,
) {
    let mut parsed = false;
    let mut unparseable: Option<Inspection> = None;
    for cp in candidates {
        if cp.exists() {
            let (f, insp) = inspect_mcp_file(cp, scope);
            findings.extend(f);
            if matches!(insp.status, InspectionStatus::Inspected { .. }) {
                parsed = true;
            } else if unparseable.is_none() {
                unparseable = Some(insp);
            }
        }
    }
    if let Some(sp) = settings_path {
        if sp.exists() {
            if let Ok(content) = std::fs::read_to_string(sp) {
                match parse_json_value(&content) {
                    Ok(v) => {
                        if has_mcp_config(&v) {
                            let (f, insp) = inspect_mcp_content(
                                &content,
                                Some(&sp.display().to_string()),
                                scope,
                            );
                            findings.extend(f);
                            if matches!(insp.status, InspectionStatus::Inspected { .. }) {
                                parsed = true;
                            }
                        }
                    }
                    Err(err) => {
                        let (f, insp) =
                            unparseable_result(err, Some(&sp.display().to_string()), scope);
                        findings.push(f);
                        if unparseable.is_none() {
                            unparseable = Some(insp);
                        }
                    }
                }
            }
        }
    }
    if parsed {
        inspections.push(Inspection::inspected(
            Category::AgentAudit,
            Some(MCP_SUB_CATEGORY),
            scope,
        ));
    } else if let Some(insp) = unparseable {
        inspections.push(insp);
    } else {
        inspections.push(Inspection::skipped(
            Category::AgentAudit,
            Some(MCP_SUB_CATEGORY),
            Some("file not present"),
        ));
    }
}

fn unparseable_result(err: String, file_path: Option<&str>, scope: &str) -> (Finding, Inspection) {
    let loc = file_path.unwrap_or("content");
    let is_toml = loc.ends_with(".toml");
    let syntax_desc = if is_toml { "TOML" } else { "JSON" };
    let mut f = Finding::new(
        format!("mcp-config-unparseable:{loc}"),
        "Unparseable MCP configuration file",
        Category::AgentAudit,
        Severity::Medium,
        format!("Failed to parse MCP configuration file: {err}"),
    )
    .with_sub_category(MCP_SUB_CATEGORY)
    .with_scope(scope)
    .with_remediation(format!(
        "Verify that the configuration file exists and has valid {syntax_desc} syntax."
    ));
    if let Some(p) = file_path {
        f = f.with_location(p, Some(1));
    }
    (
        f,
        Inspection::unparseable(Category::AgentAudit, Some(MCP_SUB_CATEGORY), file_path, err),
    )
}

fn read_file_or_unparseable(
    path: &Path,
    scope: &str,
) -> Result<String, Box<(Finding, Inspection)>> {
    let p = path.display().to_string();
    std::fs::read_to_string(path)
        .map_err(|e| Box::new(unparseable_result(e.to_string(), Some(&p), scope)))
}

pub fn inspect_claude_json_file(path: &Path) -> (Vec<Finding>, Vec<Inspection>) {
    if !path.exists() {
        return (
            Vec::new(),
            vec![Inspection::skipped(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                Some("file not present"),
            )],
        );
    }
    match read_file_or_unparseable(path, "user") {
        Ok(c) => inspect_claude_json_content(&c, Some(&path.display().to_string())),
        Err(err) => (vec![err.0], vec![err.1]),
    }
}

pub fn inspect_claude_json_content(
    content: &str,
    file_path: Option<&str>,
) -> (Vec<Finding>, Vec<Inspection>) {
    let (mut findings, mut inspections) = (Vec::new(), Vec::new());
    let val = match parse_json_value(content) {
        Ok(v) => v,
        Err(err) => {
            let (f, insp) = unparseable_result(err, file_path, "user");
            return (vec![f], vec![insp]);
        }
    };

    let servers = val.get("mcpServers").and_then(|s| s.as_object());
    let scope_u = if servers.is_some() {
        "user (~/.claude.json)"
    } else {
        "user (~/.claude.json empty)"
    };
    for (name, conf) in servers.into_iter().flatten() {
        inspect_server_entry(name, conf, content, file_path, scope_u, None, &mut findings);
    }
    inspections.push(Inspection::inspected(
        Category::AgentAudit,
        Some(MCP_SUB_CATEGORY),
        scope_u,
    ));

    for (pk, pv) in val
        .get("projects")
        .and_then(|p| p.as_object())
        .into_iter()
        .flatten()
    {
        if let Some(s) = pv.get("mcpServers").and_then(|s| s.as_object()) {
            let sc = format!("proj:{pk}");
            for (n, c) in s {
                inspect_server_entry(n, c, content, file_path, &sc, Some(pk), &mut findings);
            }
            inspections.push(Inspection::inspected(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                sc,
            ));
        }
    }
    (findings, inspections)
}

pub fn inspect_mcp_file(path: &Path, scope: &str) -> (Vec<Finding>, Inspection) {
    if !path.exists() {
        return (
            Vec::new(),
            Inspection::skipped(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                Some("file not present"),
            ),
        );
    }
    match read_file_or_unparseable(path, scope) {
        Ok(c) => inspect_mcp_content(&c, Some(&path.display().to_string()), scope),
        Err(err) => (vec![err.0], err.1),
    }
}

pub fn inspect_mcp_content(
    content: &str,
    file_path: Option<&str>,
    scope: &str,
) -> (Vec<Finding>, Inspection) {
    let mut findings = Vec::new();
    let val = match parse_json_value(content) {
        Ok(v) => v,
        Err(err) => {
            let (f, i) = unparseable_result(err, file_path, scope);
            return (vec![f], i);
        }
    };
    let pk = scope.strip_prefix("proj:").map(|k| k.trim_end_matches(':'));
    let servers = val
        .get("mcpServers")
        .or_else(|| val.get("servers"))
        .or_else(|| val.get("mcp.servers"))
        .or_else(|| val.get("mcp").and_then(|m| m.get("servers")))
        .and_then(|s| s.as_object());
    for (n, c) in servers.into_iter().flatten().filter(|(_, c)| c.is_object()) {
        inspect_server_entry(n, c, content, file_path, scope, pk, &mut findings);
    }
    (
        findings,
        Inspection::inspected(Category::AgentAudit, Some(MCP_SUB_CATEGORY), scope),
    )
}

pub fn inspect_codex_toml_file(path: &Path, scope: &str) -> (Vec<Finding>, Inspection) {
    if !path.exists() {
        return (
            Vec::new(),
            Inspection::skipped(
                Category::AgentAudit,
                Some(MCP_SUB_CATEGORY),
                Some("file not present"),
            ),
        );
    }
    let p = path.display().to_string();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            let (f, insp) = unparseable_result(e.to_string(), Some(&p), scope);
            return (vec![f], insp);
        }
    };
    inspect_codex_toml_content(&content, Some(&p), scope)
}

pub fn inspect_codex_toml_content(
    content: &str,
    file_path: Option<&str>,
    scope: &str,
) -> (Vec<Finding>, Inspection) {
    let mut findings = Vec::new();
    let val: toml::Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(err) => {
            let (f, i) = unparseable_result(err.to_string(), file_path, scope);
            return (vec![f], i);
        }
    };
    let pk = scope.strip_prefix("proj:").map(|k| k.trim_end_matches(':'));
    let mcp_servers = val
        .get("mcp_servers")
        .or_else(|| val.get("mcpServers"))
        .or_else(|| val.get("mcp-servers"));

    if let Some(servers_val) = mcp_servers {
        if let Some(table) = servers_val.as_table() {
            if table.contains_key("command") || table.contains_key("url") {
                if let Ok(json_val) = serde_json::to_value(servers_val) {
                    inspect_server_entry(
                        "default",
                        &json_val,
                        content,
                        file_path,
                        scope,
                        pk,
                        &mut findings,
                    );
                }
            } else {
                for (name, conf_val) in table {
                    if conf_val.is_table() {
                        if let Ok(json_val) = serde_json::to_value(conf_val) {
                            inspect_server_entry(
                                name,
                                &json_val,
                                content,
                                file_path,
                                scope,
                                pk,
                                &mut findings,
                            );
                        }
                    }
                }
            }
        }
    }
    (
        findings,
        Inspection::inspected(Category::AgentAudit, Some(MCP_SUB_CATEGORY), scope),
    )
}

pub(crate) fn inspect_server_entry(
    server_name: &str,
    conf: &Value,
    content: &str,
    file_path: Option<&str>,
    scope: &str,
    project_key: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    let pfx = project_key
        .or_else(|| scope.strip_prefix("proj:").map(|k| k.trim_end_matches(':')))
        .map_or_else(String::new, |k| format!("proj:{k}:"));
    let mut emit = |sfx: &str,
                    t: String,
                    (sev, line): (Severity, Option<usize>),
                    d: String,
                    r: Option<&str>| {
        let mut f = Finding::new(format!("{pfx}{sfx}"), t, Category::AgentAudit, sev, d)
            .with_sub_category(MCP_SUB_CATEGORY)
            .with_scope(scope);
        if let Some(rem) = r {
            f = f.with_remediation(rem);
        }
        if let Some(p) = file_path {
            f = f.with_location(p, line);
        }
        findings.push(f);
    };

    let cmd_str = conf.get("command").and_then(|c| c.as_str()).unwrap_or("");
    let url_str = conf.get("url").and_then(|u| u.as_str()).unwrap_or("");
    let args: Vec<String> = conf
        .get("args")
        .and_then(|a| a.as_array())
        .into_iter()
        .flatten()
        .filter_map(|i| i.as_str().map(String::from))
        .collect();

    let mut tokens = split_command_tokens(cmd_str);
    tokens.extend(args.clone());

    let srv_line = find_server_key_line(content, project_key, server_name, server_name);
    let summary = if !cmd_str.is_empty() {
        format!(
            "command '{}'",
            tokens.first().map_or(cmd_str, String::as_str)
        )
    } else if !url_str.is_empty() {
        "remote endpoint".into()
    } else {
        "custom entry".into()
    };
    emit(
        &format!("mcp-server-inventory:{server_name}"),
        format!("Configured MCP server '{server_name}' ({summary})"),
        (Severity::Info, srv_line),
        format!(
            "MCP server '{server_name}' is configured in {}.",
            file_path.unwrap_or(scope)
        ),
        None,
    );

    if tokens
        .first()
        .is_some_and(|tok| tok == "npx" || tok.ends_with("/npx"))
    {
        if let Some(pkg) =
            extract_npx_package_candidate(&tokens).filter(|p| is_unpinned_npm_package(p))
        {
            let line = find_server_key_line(content, project_key, server_name, pkg)
                .or_else(|| find_server_key_line(content, project_key, server_name, "command"));
            let (base_name, _) = parse_npm_package(pkg);
            let cmd_pfx = if tokens.iter().any(|t| t == "-y" || t == "--yes") {
                "npx -y"
            } else {
                "npx"
            };
            let rem = format!("Pin the package to an exact semver version (e.g. {cmd_pfx} {base_name}@<version>).");
            emit(
                &format!("mcp-unpinned-npx:{server_name}"),
                format!("MCP server '{server_name}' runs unpinned package with {cmd_pfx}: {pkg}"),
                (Severity::Medium, line),
                format!("Running {cmd_pfx} with unpinned package '{pkg}' fetches non-exact releases at startup."),
                Some(&rem),
            );
        }
    }

    let mut check_url = |url: &str, id: String, key: &str| {
        if has_url_basic_auth(url) {
            emit(
                &id,
                format!("HTTP Basic Auth credentials exposed in server '{server_name}' URL"),
                (Severity::High, find_server_key_line(content, project_key, server_name, key)),
                format!("Hosted MCP server '{server_name}' URL contains embedded credentials in the authority."),
                Some(REM_URL),
            );
        }
    };
    if !url_str.is_empty() {
        check_url(url_str, format!("mcp-basic-auth:{server_name}"), "url");
    }
    for (idx, arg) in tokens.iter().enumerate().filter(|(_, a)| a.contains("://")) {
        check_url(arg, format!("mcp-basic-auth:{server_name}:arg:{idx}"), arg);
    }

    for (sec_name, sec_val) in [("env", conf.get("env")), ("header", conf.get("headers"))] {
        for (k, v) in sec_val.and_then(|v| v.as_object()).into_iter().flatten() {
            if v.as_str()
                .is_some_and(|s| is_secret_key(k) && is_plaintext_secret_value(s))
            {
                emit(
                    &format!("mcp-plaintext-secret:{server_name}:{sec_name}:{k}"),
                    format!("Plaintext credential in server '{server_name}' {sec_name}: {k}"),
                    (Severity::High, find_server_key_line(content, project_key, server_name, k)),
                    format!("Server '{server_name}' defines credential {sec_name} '{k}' in plaintext configuration."),
                    Some(REM_ENV),
                );
            }
        }
    }

    let mut i = 0;
    while i < args.len() {
        let (arg, arg_idx) = (&args[i], i);
        let flag = if let Some((f, v)) = arg.split_once('=') {
            (is_secret_key(f) && is_plaintext_secret_value(v)).then(|| f.to_string())
        } else if is_secret_key(arg)
            && args
                .get(i + 1)
                .is_some_and(|nx| !nx.starts_with('-') && is_plaintext_secret_value(nx))
        {
            i += 1;
            Some(arg.to_string())
        } else {
            None
        };
        if let Some(f) = flag {
            emit(
                &format!("mcp-plaintext-secret:{server_name}:arg:{arg_idx}"),
                format!("Plaintext credential in server '{server_name}' command argument [{arg_idx}]"),
                (Severity::High, find_server_key_line(content, project_key, server_name, "args")),
                format!("Server '{server_name}' defines plaintext credential parameter '{f}' in command arguments."),
                Some(REM_ARG),
            );
        }
        i += 1;
    }
}

pub fn split_command_tokens(cmd: &str) -> Vec<String> {
    let (mut tokens, mut cur, mut quote, mut esc) = (Vec::new(), String::new(), None, false);
    for ch in cmd.chars() {
        if esc {
            cur.push(ch);
            esc = false;
        } else if ch == '\\' && quote != Some('\'') {
            esc = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && (ch == '\'' || ch == '"') {
            quote = Some(ch);
        } else if ch.is_whitespace() && quote.is_none() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub fn extract_npx_package_candidate(tokens: &[String]) -> Option<&str> {
    let bools = "y yes q quiet no no-install p package i";
    let vals = "registry prefix header userconfig disturl cache node-options workspace w scope target cafile cert key cwd dir c extra-index-url index-url config env-file auth";
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "npx" || tok.ends_with("/npx") {
            i += 1;
        } else if tok.starts_with('-') {
            let clean = tok.trim_start_matches('-').to_ascii_lowercase();
            let takes_val = !tok.contains('=')
                && (vals.split_whitespace().any(|f| f == clean)
                    || is_secret_key(tok)
                    || (tok.starts_with("--") && !bools.split_whitespace().any(|f| f == clean)));
            i += if takes_val { 2 } else { 1 };
        } else if !tok.contains("://") && !is_path_like(tok) {
            return Some(tok);
        } else {
            i += 1;
        }
    }
    None
}

pub fn parse_npm_package(pkg: &str) -> (&str, Option<&str>) {
    let s = pkg.trim();
    if let Some(rest) = s.strip_prefix('@') {
        rest.find('@')
            .map_or((s, None), |idx| (&s[..idx + 1], Some(&rest[idx + 1..])))
    } else {
        s.find('@')
            .map_or((s, None), |idx| (&s[..idx], Some(&s[idx + 1..])))
    }
}

pub fn is_exact_semver(v: &str) -> bool {
    let valid_id = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    };
    let v_no_build = match v.trim().split_once('+') {
        Some((pre_b, b)) if valid_id(b) => pre_b,
        Some(_) => return false,
        None => v.trim(),
    };
    let (base, pre) = v_no_build
        .split_once('-')
        .map_or((v_no_build, None), |(b, p)| (b, Some(p)));
    let parts: Vec<&str> = base.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && pre.is_none_or(valid_id)
}

pub fn is_unpinned_npm_package(pkg: &str) -> bool {
    !pkg.trim().is_empty() && parse_npm_package(pkg).1.is_none_or(|v| !is_exact_semver(v))
}

pub fn has_url_basic_auth(url_str: &str) -> bool {
    let t = url_str.trim();
    let l = t.to_ascii_lowercase();
    let after = if l.starts_with("http://") {
        &t[7..]
    } else if l.starts_with("https://") {
        &t[8..]
    } else {
        return false;
    };
    let auth = after.split(['/', '?', '#']).next().unwrap_or(after);
    auth.rfind('@')
        .and_then(|at| auth[..at].split_once(':'))
        .is_some_and(|(u, p)| !u.is_empty() && !p.is_empty())
}

pub fn is_secret_key(key: &str) -> bool {
    let u = key
        .trim_start_matches('-')
        .to_ascii_uppercase()
        .replace('-', "_");
    if "_PATH _DIR _FILE _URL _FOLDER _SOCK"
        .split_whitespace()
        .any(|s| u.ends_with(s))
        || "PATH DIR FILE URL FOLDER SOCK HOME NODE_PATH PYTHONPATH"
            .split_whitespace()
            .any(|s| s == u)
    {
        return false;
    }
    let pairs =
        "API_KEY AUTH_TOKEN ACCESS_KEY PRIVATE_KEY CLIENT_SECRET SECRET_KEY AUTHORIZATION BEARER";
    let segs = "TOKEN SECRET PASSWORD PASSWD APIKEY CREDENTIALS CREDENTIAL BEARER";
    pairs
        .split_whitespace()
        .any(|p| u == p || u.ends_with(&format!("_{p}")))
        || u.split(['_', '.', ':'])
            .any(|seg| segs.split_whitespace().any(|k| k == seg))
}

pub fn is_path_like(val: &str) -> bool {
    let v = val.trim();
    !v.is_empty()
        && !v.ends_with('=')
        && !v.contains('+')
        && "/ ~/ ./ ../ file://"
            .split_whitespace()
            .any(|p| v.starts_with(p))
}

pub fn is_plaintext_secret_value(val: &str) -> bool {
    let v = val.trim();
    v.len() >= 8 && !v.starts_with('$') && !v.contains("${") && !is_path_like(v)
}

pub fn parse_json_value(content: &str) -> Result<Value, String> {
    serde_json::from_str::<Value>(content).or_else(|_| {
        serde_json::from_str::<Value>(&strip_json_comments_and_trailing_commas(content))
            .map_err(|e| e.to_string())
    })
}

fn strip_json_comments_and_trailing_commas(input: &str) -> String {
    let (mut out, mut in_str, mut prev) = (String::with_capacity(input.len()), false, ' ');
    for line in input.lines().filter(|l| !l.trim().starts_with("//")) {
        for c in line.chars() {
            if c == '"' && prev != '\\' {
                in_str = !in_str;
            } else if !in_str && c == '/' && prev == '/' {
                out.truncate(out.len() - 1);
                break;
            }
            out.push(c);
            prev = c;
        }
        out.push('\n');
    }
    let ch: Vec<char> = out.chars().collect();
    ch.iter()
        .enumerate()
        .filter(|&(i, &c)| {
            !(c == ','
                && matches!(
                    ch[i + 1..].iter().find(|x| !x.is_whitespace()),
                    Some('}' | ']')
                ))
        })
        .map(|(_, &c)| c)
        .collect()
}

fn find_server_key_line(
    content: &str,
    project_key: Option<&str>,
    server_name: &str,
    key: &str,
) -> Option<usize> {
    let (key_q, srv_q) = (format!("\"{key}\""), format!("\"{server_name}\""));
    let lines: Vec<&str> = content.lines().collect();
    let p_start = project_key
        .and_then(|pk| lines.iter().position(|l| l.contains(&format!("\"{pk}\""))))
        .unwrap_or(0);
    let s_start = lines[p_start..]
        .iter()
        .position(|l| {
            l.contains(&srv_q)
                || l.contains(&format!(".{server_name}"))
                || l.contains(&format!("[{server_name}]"))
                || l.contains(&format!("{server_name} ="))
                || l.contains(&format!("{server_name}="))
        })
        .map_or(p_start, |idx| p_start + idx);
    lines[s_start..]
        .iter()
        .take(60)
        .position(|l| l.contains(&key_q) || l.contains(key))
        .map(|idx| s_start + idx + 1)
}

fn compute_relative_scope_path(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{InspectionStatus, ScanResult};
    use crate::report::render_report;
    use std::fs;

    #[test]
    fn test_unpinned_and_scoped_npx() {
        for ok in [
            "@scope/pkg@1.2.3",
            "pkg@0.4.1-alpha.2",
            "pkg@1.2.3-rc-1",
            "pkg@1.2.3+20130313",
        ] {
            assert!(!is_unpinned_npm_package(ok), "{ok}");
        }
        for bad in [
            "@scope/pkg@latest",
            "@scope/pkg",
            "pkg@^1.0.0",
            "pkg@~1.2",
            "pkg@next",
            "pkg@*",
        ] {
            assert!(is_unpinned_npm_package(bad), "{bad}");
        }
        assert_eq!(parse_npm_package("@scope/pkg@latest").0, "@scope/pkg");

        let j1 = r#"{"mcpServers":{"fs":{"command":"npx -y @scope/fs@latest /tmp"}}}"#;
        let (f1, _) = inspect_mcp_content(j1, None, "user");
        assert!(f1.iter().any(|f| f.id == "mcp-unpinned-npx:fs"));
        assert!(f1
            .iter()
            .any(|f| f.id == "mcp-server-inventory:fs" && f.severity == Severity::Info));

        let sec = format!("sk-ant-{}", "a".repeat(24));
        let jf = format!(
            r#"{{"mcpServers":{{"s":{{"command":"npx","args":["--api-key","{sec}","@scope/ok@1.2.3"]}}}}}}"#
        );
        let (ff, _) = inspect_mcp_content(&jf, None, "user");
        assert!(!ff
            .iter()
            .any(|f| f.title.contains(&sec) || f.id.contains("unpinned")));
    }

    #[test]
    fn test_basic_auth_in_hosted_urls() {
        let pw = ["sec", "ret", "123"].concat();
        let j = format!(
            r#"{{"mcpServers":{{"remote":{{"url":"https://admin:{pw}@remote.internal/sse"}},"user_only":{{"url":"https://user@remote.internal/sse"}},"ssh":{{"command":"git","args":["ssh://git@github.com/org/repo.git"]}}}}}}"#
        );
        let (findings, _) = inspect_mcp_content(&j, None, "user");
        let auth_ids: Vec<&str> = findings
            .iter()
            .filter(|f| f.id.contains("basic-auth"))
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(auth_ids, vec!["mcp-basic-auth:remote"]);
    }

    #[test]
    fn test_plaintext_secrets_detection_and_false_alarms() {
        let (aws, b64, tok) = (
            ["AKIA", &"X".repeat(16)].concat(),
            format!("{}==", "aB1c".repeat(6)),
            format!("Bearer sk-{}", "z".repeat(20)),
        );
        let j = format!(
            r#"{{"mcpServers":{{"cloud":{{"args":["--token-file","/Volumes/x","--api-key","{aws}"],"env":{{"AWS_SECRET_ACCESS_KEY":"{aws}","BASE64_TOKEN":"{b64}","CONFIG_PATH":"/Users/dev/.config/key.json","AUTH_FILE":"./certs/auth.pem","INTERPOLATED_KEY":"${{SECRET_KEY}}","AUTHOR_NAME":"Alice Smith","COMPATIBILITY_MODE":"strict-v2-mode","TOKENIZER":"cl100k_base_v1","KEYBOARD_LAYOUT":"us-intl-mac","BYPASS_CACHE":"enabled-always","SSH_AUTH_SOCK":"/private/tmp/com.apple.launchd/Listeners"}},"headers":{{"Authorization":"{tok}"}}}}}}}}"#
        );
        let (findings, _) = inspect_mcp_content(&j, None, "user");
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        for exp in [
            "env:AWS_SECRET_ACCESS_KEY",
            "env:BASE64_TOKEN",
            "header:Authorization",
            "arg:2",
        ] {
            assert!(
                ids.iter().any(|id| id.ends_with(exp)),
                "Missing {exp}: {ids:?}"
            );
        }
        let clean = "CONFIG_PATH AUTH_FILE INTERPOLATED_KEY AUTHOR_NAME COMPATIBILITY_MODE TOKENIZER KEYBOARD BYPASS SSH_AUTH_SOCK arg:0";
        for c in clean.split_whitespace() {
            assert!(
                !ids.iter().any(|id| id.contains(c)),
                "False alarm on {c}: {ids:?}"
            );
        }
    }

    #[test]
    fn test_project_scoping_and_line_numbers() {
        let j = "{\n  \"mcpServers\": {\n    \"db\": {\n      \"command\": \"npx -y db-mcp@latest\"\n    }\n  },\n  \"projects\": {\n    \"/Users/dev/project-alpha\": {\n      \"mcpServers\": {\n        \"db\": {\n          \"command\": \"npx -y db-mcp@latest\"\n        }\n      }\n    }\n  }\n}";
        let (f, insp) = inspect_claude_json_content(j, Some("~/.claude.json"));
        let g = f.iter().find(|x| x.id == "mcp-unpinned-npx:db").unwrap();
        let p = f
            .iter()
            .find(|x| x.id == "proj:/Users/dev/project-alpha:mcp-unpinned-npx:db")
            .unwrap();
        assert_eq!(
            (g.line_number, p.line_number, insp.len()),
            (Some(4), Some(11), 2)
        );
    }

    #[test]
    fn test_vscode_child_repos_and_report_rendering() {
        let (fb, ib) = inspect_mcp_content("{ broken json ", Some("test.json"), "proj:repo");
        assert_eq!(fb[0].id, "mcp-config-unparseable:test.json");
        assert!(matches!(
            ib.status,
            InspectionStatus::UnparseableData { .. }
        ));
        assert!(inspect_mcp_content(r#"{"version":"1.0"}"#, None, "user")
            .0
            .is_empty());

        let dir = std::env::temp_dir().join(format!("macflow_mcp_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let app = dir.join("projects/app");
        fs::create_dir_all(app.join(".vscode")).unwrap();
        fs::write(
            dir.join(".claude.json"),
            r#"{"mcpServers":{"global-srv":{"command":"npx -y @scope/pkg@1.2.3"}}}"#,
        )
        .unwrap();
        fs::write(
            app.join(".mcp.json"),
            r#"{"mcpServers":{"app-srv":{"command":"npx -y @scope/app@latest"}}}"#,
        )
        .unwrap();
        fs::write(
            app.join(".vscode/mcp.json"),
            r#"{"servers":{"vs-srv":{"command":"npx -y @scope/vs@1.0.0"}}}"#,
        )
        .unwrap();

        let (f, insp) =
            scan_mcp_servers_with_home(&ScanContext::new().with_roots(vec![]), Some(&dir));
        let ids: Vec<&str> = f.iter().map(|x| x.id.as_str()).collect();
        for exp in [
            "inventory:global-srv",
            "unpinned-npx:app-srv",
            "inventory:vs-srv",
        ] {
            assert!(
                ids.iter().any(|id| id.contains(exp)),
                "Missing {exp}: {ids:?}"
            );
        }
        let r = render_report(&ScanResult::new(f, insp, "2026-10-21T00:00:00Z"));
        assert!(
            !r.contains("scope unknown") && !r.contains("Other findings"),
            "{r}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cursor_mcp_parsing_and_rule_firing() {
        let cursor_json = r#"{
  "mcpServers": {
    "cursor-tool": {
      "command": "npx -y @cursor/pkg@latest",
      "env": {
        "CURSOR_API_KEY": "supersecretcursor123"
      }
    }
  }
}"#;
        let (findings, insp) = inspect_mcp_content(
            cursor_json,
            Some("/home/dev/.cursor/mcp.json"),
            "user:cursor",
        );
        assert_eq!(
            insp.status,
            InspectionStatus::Inspected {
                inspected_scope: "user:cursor".into()
            }
        );
        for f in &findings {
            assert_eq!(f.scope.as_deref(), Some("user:cursor"));
        }
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"mcp-server-inventory:cursor-tool"));
        assert!(ids.contains(&"mcp-unpinned-npx:cursor-tool"));
        assert!(ids.contains(&"mcp-plaintext-secret:cursor-tool:env:CURSOR_API_KEY"));
    }

    #[test]
    fn test_codex_config_toml_parsing_and_rule_firing() {
        let codex_toml = r#"
[projects."/Users/dev/myproject"]
trust_level = "trusted"

[mcp_servers.codex-unpinned]
command = "npx"
args = ["-y", "codex-helper@latest"]

[mcp_servers.codex-remote]
url = "https://user:pass123456@codex.internal/mcp"

[mcp_servers.codex-secret]
command = "python"
args = ["--token", "verysecretpassword123"]
[mcp_servers.codex-secret.env]
OPENAI_API_KEY = "sk-proj-supersecretkey12345"
"#;
        let (findings, insp) = inspect_codex_toml_content(
            codex_toml,
            Some("/home/dev/.codex/config.toml"),
            "user:codex",
        );
        assert_eq!(
            insp.status,
            InspectionStatus::Inspected {
                inspected_scope: "user:codex".into()
            }
        );
        for f in &findings {
            assert_eq!(f.scope.as_deref(), Some("user:codex"));
        }
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"mcp-server-inventory:codex-unpinned"));
        assert!(ids.contains(&"mcp-unpinned-npx:codex-unpinned"));
        assert!(ids.contains(&"mcp-basic-auth:codex-remote"));
        assert!(ids.contains(&"mcp-plaintext-secret:codex-secret:arg:0"));
        assert!(ids.contains(&"mcp-plaintext-secret:codex-secret:env:OPENAI_API_KEY"));

        // Test invalid TOML syntax produces unparseable inspection
        let (unp_f, unp_insp) = inspect_codex_toml_content(
            "mcp_servers = [ invalid syntax",
            Some("broken.toml"),
            "user:codex",
        );
        assert_eq!(unp_f[0].id, "mcp-config-unparseable:broken.toml");
        assert!(matches!(
            unp_insp.status,
            InspectionStatus::UnparseableData { .. }
        ));
    }

    #[test]
    fn test_windsurf_vscode_and_antigravity_fixture_parsing() {
        // Windsurf
        let windsurf_json = r#"{
  "mcpServers": {
    "windsurf-tool": {
      "command": "npx -y windsurf-code@latest"
    }
  }
}"#;
        let (w_f, w_insp) = inspect_mcp_content(
            windsurf_json,
            Some("/home/dev/.codeium/windsurf/mcp_config.json"),
            "user:windsurf",
        );
        assert_eq!(
            w_insp.status,
            InspectionStatus::Inspected {
                inspected_scope: "user:windsurf".into()
            }
        );
        assert_eq!(w_f[1].scope.as_deref(), Some("user:windsurf"));
        assert_eq!(w_f[1].id, "mcp-unpinned-npx:windsurf-tool");

        // VS Code settings.json format with "mcp.servers"
        let vscode_settings_json = r#"{
  "editor.fontSize": 14,
  "mcp.servers": {
    "vscode-tool": {
      "command": "npx -y vscode-ext@latest"
    }
  }
}"#;
        let (v_f, v_insp) = inspect_mcp_content(
            vscode_settings_json,
            Some("/home/dev/Library/Application Support/Code/User/settings.json"),
            "user:vscode",
        );
        assert_eq!(
            v_insp.status,
            InspectionStatus::Inspected {
                inspected_scope: "user:vscode".into()
            }
        );
        assert_eq!(v_f[1].scope.as_deref(), Some("user:vscode"));
        assert_eq!(v_f[1].id, "mcp-unpinned-npx:vscode-tool");

        // Antigravity format
        let agy_json = r#"{
  "mcpServers": {
    "agy-remote": {
      "url": "https://service:secretpass123@agy.internal/mcp"
    }
  }
}"#;
        let (a_f, a_insp) = inspect_mcp_content(
            agy_json,
            Some("/home/dev/.gemini/antigravity/mcp.json"),
            "user:antigravity",
        );
        assert_eq!(
            a_insp.status,
            InspectionStatus::Inspected {
                inspected_scope: "user:antigravity".into()
            }
        );
        assert_eq!(a_f[1].scope.as_deref(), Some("user:antigravity"));
        assert_eq!(a_f[1].id, "mcp-basic-auth:agy-remote");
    }

    #[test]
    fn test_missing_files_produce_clean_skipped_inspections() {
        let empty_dir =
            std::env::temp_dir().join(format!("macflow_mcp_empty_{}", std::process::id()));
        let _ = fs::remove_dir_all(&empty_dir);
        fs::create_dir_all(&empty_dir).unwrap();

        let (findings, inspections) =
            scan_mcp_servers_with_home(&ScanContext::new().with_roots(vec![]), Some(&empty_dir));
        assert!(
            findings.is_empty(),
            "Expected 0 findings for empty home: {findings:?}"
        );

        // All missing configs must produce skipped inspections with reason "file not present"
        assert!(!inspections.is_empty());
        for insp in &inspections {
            match &insp.status {
                InspectionStatus::Skipped { reason: Some(r) } => {
                    assert_eq!(r, "file not present", "Unexpected skip reason: {r}");
                }
                other => panic!("Expected clean skipped inspection, got: {other:?}"),
            }
        }

        // Direct inspect_*_file calls on non-existent paths
        let non_existent = empty_dir.join("non_existent_file.json");
        let (f_mcp, i_mcp) = inspect_mcp_file(&non_existent, "user:cursor");
        assert!(f_mcp.is_empty());
        assert_eq!(
            i_mcp.status,
            InspectionStatus::Skipped {
                reason: Some("file not present".into())
            }
        );

        let non_existent_toml = empty_dir.join("non_existent.toml");
        let (f_toml, i_toml) = inspect_codex_toml_file(&non_existent_toml, "user:codex");
        assert!(f_toml.is_empty());
        assert_eq!(
            i_toml.status,
            InspectionStatus::Skipped {
                reason: Some("file not present".into())
            }
        );

        let (f_cj, i_cj) = inspect_claude_json_file(&non_existent);
        assert!(f_cj.is_empty());
        assert_eq!(
            i_cj[0].status,
            InspectionStatus::Skipped {
                reason: Some("file not present".into())
            }
        );

        let _ = fs::remove_dir_all(&empty_dir);
    }

    #[test]
    fn test_strict_offline_zero_secret_values_exposed() {
        let secret1 = "SECRET_SUPER_TOKEN_VAL_987654";
        let secret2 = "CONFIDENTIAL_PASSWORD_VAL_123456";
        let secret3 = "sk-proj-ACTUAL_SECRET_KEY_ABCDEF";

        let json_content = format!(
            r#"{{
  "mcpServers": {{
    "sec-server": {{
      "command": "npx",
      "args": ["--api-key", "{secret1}", "tool-pkg@1.0.0"],
      "env": {{
        "DB_PASS": "{secret2}"
      }}
    }}
  }}
}}"#
        );
        let (f_json, _) = inspect_mcp_content(&json_content, Some("test.json"), "user:cursor");

        let toml_content = format!(
            r#"
[mcp_servers.sec-toml]
command = "node"
args = ["--auth-token", "{secret1}"]
[mcp_servers.sec-toml.env]
OPENAI_API_KEY = "{secret3}"
"#
        );
        let (f_toml, _) =
            inspect_codex_toml_content(&toml_content, Some("test.toml"), "user:codex");

        let all_findings = [f_json, f_toml].concat();
        assert!(!all_findings.is_empty());

        for f in &all_findings {
            for secret in [secret1, secret2, secret3] {
                assert!(
                    !f.id.contains(secret),
                    "Finding ID leaked sensitive secret: {}",
                    f.id
                );
                assert!(
                    !f.title.contains(secret),
                    "Finding title leaked sensitive secret: {}",
                    f.title
                );
                assert!(
                    !f.description.contains(secret),
                    "Finding description leaked sensitive secret: {}",
                    f.description
                );
                if let Some(rem) = &f.remediation {
                    assert!(
                        !rem.contains(secret),
                        "Finding remediation leaked sensitive secret: {rem}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_antigravity_multiple_config_files_no_duplicate_inspections() {
        let dir =
            std::env::temp_dir().join(format!("macflow_mcp_agy_multi_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let agy_dir = dir.join(".gemini/antigravity");
        fs::create_dir_all(&agy_dir).unwrap();

        fs::write(
            agy_dir.join("mcp_config.json"),
            r#"{"mcpServers":{"risky-tool":{"command":"npx -y @evil/tool@latest"}}}"#,
        )
        .unwrap();

        fs::write(
            dir.join(".gemini/settings.json"),
            r#"{"mcpServers":{"safe-tool":{"command":"node","args":["server.js"]}}}"#,
        )
        .unwrap();

        let ctx = ScanContext::new().with_roots(vec![]);
        let (findings, inspections) = scan_mcp_servers_with_home(&ctx, Some(&dir));

        let agy_inspections: Vec<&Inspection> = inspections
            .iter()
            .filter(|i| match &i.status {
                InspectionStatus::Inspected { inspected_scope } => {
                    inspected_scope == "user:antigravity"
                }
                _ => false,
            })
            .collect();
        assert_eq!(
            agy_inspections.len(),
            1,
            "Expected exactly 1 inspection for user:antigravity, got {}",
            agy_inspections.len()
        );

        let report = render_report(&ScanResult::new(
            findings,
            inspections,
            "2026-10-24T00:00:00Z",
        ));
        assert!(report.contains("risky-tool") || report.contains("unpinned"));
        assert!(
            !report.contains("- MCP servers: no known match (user:antigravity)"),
            "Report contained contradictory 'no known match':\n{report}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_vscode_multiple_config_files_no_duplicate_inspections() {
        let dir =
            std::env::temp_dir().join(format!("macflow_mcp_vscode_multi_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let code_user_dir = dir.join("Library/Application Support/Code/User");
        fs::create_dir_all(&code_user_dir).unwrap();

        fs::write(
            code_user_dir.join("mcp.json"),
            r#"{"mcpServers":{"vscode-tool":{"command":"npx -y @vscode/tool@latest"}}}"#,
        )
        .unwrap();

        fs::write(
            code_user_dir.join("settings.json"),
            r#"{"editor.fontSize":14,"mcp.servers":{"extra-tool":{"command":"node"}}}"#,
        )
        .unwrap();

        let ctx = ScanContext::new().with_roots(vec![]);
        let (findings, inspections) = scan_mcp_servers_with_home(&ctx, Some(&dir));

        let vscode_inspections: Vec<&Inspection> = inspections
            .iter()
            .filter(|i| match &i.status {
                InspectionStatus::Inspected { inspected_scope } => inspected_scope == "user:vscode",
                _ => false,
            })
            .collect();
        assert_eq!(
            vscode_inspections.len(),
            1,
            "Expected exactly 1 inspection for user:vscode, got {}",
            vscode_inspections.len()
        );

        let report = render_report(&ScanResult::new(
            findings,
            inspections,
            "2026-10-24T00:00:00Z",
        ));
        assert!(report.contains("vscode-tool") || report.contains("unpinned"));
        assert!(
            !report.contains("- MCP servers: no known match (user:vscode)"),
            "Report contained contradictory 'no known match':\n{report}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
