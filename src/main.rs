use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use macflow_scan::{
    render_json, render_report, scan_agent_autoapprove, scan_claude_plugins, scan_claude_settings,
    scan_credentials, scan_extensions, scan_garbage, scan_git_config, scan_launch_agents,
    scan_mcp_servers, scan_osv, scan_php_runtimes, scan_plaintext_keys, scan_rules_unicode,
    scan_shell, scan_ssh, scan_vscode_tasks, Category, Inspection, ScanContext, ScanResult,
};

const VERSION: &str = "macflow-check 0.1.0";

const USAGE: &str = "\
macflow-check 0.1.0
Read-only developer setup and environment scanner for macOS.

USAGE:
    macflow-check [OPTIONS] [PATHS]...

OPTIONS:
    --json           Output machine-readable JSON (schema v1)
    --offline        Skip network checks and run strictly offline
    --root <PATH>    Add a project root directory to scan (repeatable)
    -h, --help       Print this usage message
    -V, --version    Print version information
";

/// Maximum supported Unix timestamp in seconds corresponding to `9999-12-31T23:59:59Z`.
pub(crate) const MAX_SUPPORTED_UTC_SECS: u64 = 253_402_300_799;

fn format_utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_utc_timestamp_from_secs(secs)
}

/// Formats a Unix timestamp (seconds since Unix epoch `1970-01-01T00:00:00Z`)
/// into an ISO 8601 / RFC 3339 UTC date-time string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// # Algorithm
/// Implements Howard Hinnant's civil calendar algorithm from Unix epoch seconds
/// to Gregorian date and UTC time string without external `chrono` dependencies.
///
/// # Leap Seconds & POSIX Compliance
/// In accordance with POSIX / Unix time standards, leap seconds are ignored;
/// each day is treated as containing exactly 86,400 seconds.
///
/// # Date Range Bounds & Overflow Handling
/// Valid and verified for `secs` from `0` (`1970-01-01T00:00:00Z`) through
/// `253402300799` (`9999-12-31T23:59:59Z`). Values exceeding year 9999 are
/// clamped to `MAX_SUPPORTED_UTC_SECS` (`9999-12-31T23:59:59Z`) to format gracefully
/// without panics or arithmetic overflow.
pub(crate) fn format_utc_timestamp_from_secs(secs: u64) -> String {
    let secs = secs.min(MAX_SUPPORTED_UTC_SECS);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let hh = rem / 3600;
    let mm = (rem % 3600) / 60;
    let ss = rem % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn run_scan(ctx: &ScanContext) -> ScanResult {
    let mut findings = Vec::new();
    let mut inspections = Vec::new();

    if ctx.is_category_selected(Category::AgentAudit) {
        let (f_auto, i_auto) = scan_agent_autoapprove(ctx);
        findings.extend(f_auto);
        inspections.extend(i_auto);

        let (f_claude, i_claude) = scan_claude_settings(ctx);
        findings.extend(f_claude);
        inspections.extend(i_claude);

        let (f_mcp, i_mcp) = scan_mcp_servers(ctx);
        findings.extend(f_mcp);
        inspections.extend(i_mcp);

        let (f_tasks, i_tasks) = scan_vscode_tasks(ctx);
        findings.extend(f_tasks);
        inspections.extend(i_tasks);

        let (f_keys, i_keys) = scan_plaintext_keys(ctx);
        findings.extend(f_keys);
        inspections.extend(i_keys);

        let (f_plugins, i_plugins) = scan_claude_plugins(ctx);
        findings.extend(f_plugins);
        inspections.extend(i_plugins);

        let (f_rules, i_rules) = scan_rules_unicode(ctx);
        findings.extend(f_rules);
        inspections.extend(i_rules);
    } else {
        inspections.push(Inspection::skipped(
            Category::AgentAudit,
            None,
            Some("category not selected"),
        ));
    }

    if ctx.is_category_selected(Category::Security) {
        let (f_git, i_git) = scan_git_config(ctx);
        findings.extend(f_git);
        inspections.extend(i_git);

        let (f_ssh, i_ssh) = scan_ssh(ctx);
        findings.extend(f_ssh);
        inspections.extend(i_ssh);

        let (f_cred, i_cred) = scan_credentials(ctx);
        findings.extend(f_cred);
        inspections.extend(i_cred);

        let (f_php, i_php) = scan_php_runtimes(ctx);
        findings.extend(f_php);
        inspections.extend(i_php);

        let (f_ext, i_ext) = scan_extensions(ctx);
        findings.extend(f_ext);
        inspections.extend(i_ext);

        let (f_la, i_la) = scan_launch_agents(ctx);
        findings.extend(f_la);
        inspections.extend(i_la);

        let (f_osv, i_osv) = scan_osv(ctx);
        findings.extend(f_osv);
        inspections.extend(i_osv);

        let (f_shell, i_shell) = scan_shell(ctx);
        findings.extend(f_shell);
        inspections.extend(i_shell);
    } else {
        inspections.push(Inspection::skipped(
            Category::Security,
            None,
            Some("category not selected"),
        ));
    }

    let (f_garbage, i_garbage) = scan_garbage(ctx);
    findings.extend(f_garbage);
    inspections.extend(i_garbage);

    ScanResult::new(findings, inspections, format_utc_timestamp())
}

fn main() -> ExitCode {
    let mut json_mode = false;
    let mut offline = false;
    let mut roots: Vec<PathBuf> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json_mode = true,
            "--offline" => offline = true,
            "--version" | "-V" => {
                println!("{VERSION}");
                return ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--root" => {
                let Some(path) = args.next() else {
                    eprintln!("error: --root requires a path argument");
                    return ExitCode::from(2);
                };
                if path.is_empty() {
                    eprintln!("error: --root requires a non-empty path argument");
                    return ExitCode::from(2);
                }
                if path.starts_with('-') {
                    eprintln!("error: --root requires a path argument");
                    return ExitCode::from(2);
                }
                roots.push(PathBuf::from(path));
            }
            _ if arg.starts_with("--root=") => {
                let path = &arg["--root=".len()..];
                if path.is_empty() {
                    eprintln!("error: --root requires a non-empty path argument");
                    return ExitCode::from(2);
                }
                roots.push(PathBuf::from(path));
            }
            "--" => {
                for rest in args {
                    if !rest.is_empty() {
                        roots.push(PathBuf::from(rest));
                    }
                }
                break;
            }
            _ if arg.starts_with('-') => {
                eprintln!("error: unknown option '{arg}'\n\n{USAGE}");
                return ExitCode::from(2);
            }
            _ => {
                if !arg.is_empty() {
                    roots.push(PathBuf::from(arg));
                }
            }
        }
    }

    let ctx = ScanContext::new().with_roots(roots).with_offline(offline);
    let result = run_scan(&ctx);

    if json_mode {
        match render_json(&result) {
            Ok(out) => println!("{out}"),
            Err(err) => {
                eprintln!("error: failed to serialize JSON output: {err}");
                return ExitCode::from(1);
            }
        }
    } else {
        print!("{}", render_report(&result));
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_utc_timestamp_epoch_zero() {
        assert_eq!(format_utc_timestamp_from_secs(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_format_utc_timestamp_leap_day() {
        // 2024-02-29T13:00:00Z
        assert_eq!(
            format_utc_timestamp_from_secs(1709211600),
            "2024-02-29T13:00:00Z"
        );
    }

    #[test]
    fn test_format_utc_timestamp_century_and_round_years() {
        // 2030-01-01T00:00:00Z
        assert_eq!(
            format_utc_timestamp_from_secs(1893456000),
            "2030-01-01T00:00:00Z"
        );
        // Century non-leap year boundary: 2100 is not a leap year.
        // 2100-02-28T23:59:59Z followed by 2100-03-01T00:00:00Z
        assert_eq!(
            format_utc_timestamp_from_secs(4107542399),
            "2100-02-28T23:59:59Z"
        );
        assert_eq!(
            format_utc_timestamp_from_secs(4107542400),
            "2100-03-01T00:00:00Z"
        );
    }

    #[test]
    fn test_format_utc_timestamp_max_year_9999_and_clamping() {
        // Upper bound: 9999-12-31T23:59:59Z
        assert_eq!(
            format_utc_timestamp_from_secs(253402300799),
            "9999-12-31T23:59:59Z"
        );
        // Values exceeding year 9999 are clamped gracefully without panics
        assert_eq!(
            format_utc_timestamp_from_secs(253402300800),
            "9999-12-31T23:59:59Z"
        );
        assert_eq!(
            format_utc_timestamp_from_secs(u64::MAX),
            "9999-12-31T23:59:59Z"
        );
    }

    #[test]
    fn test_format_utc_timestamp_current_delegation() {
        let ts = format_utc_timestamp();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
    }
}
