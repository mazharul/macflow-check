//! The known-bad list: exact indicators from published incidents (extension releases,
//! files a backdoor drops, SSH key comments). A copy is built in; online runs also
//! download the latest list from the public repo and use it only when the owner's
//! minisign signature checks out and it is newer than the built-in copy.

use std::path::{Component, Path};
use std::process::Command;
use std::sync::OnceLock;

use serde::Deserialize;

/// Where online runs fetch the list. The signature sits next to it.
pub const LIST_URL: &str =
    "https://raw.githubusercontent.com/mazharul/macflow-check/main/known-bad/known-bad.json";

const BUILTIN_JSON: &str = include_str!("../../../known-bad/known-bad.json");
/// The owner's public key. Lists signed by any other key are ignored.
const PUBLIC_KEY: &str = include_str!("../../../known-bad/minisign.pub");

const MAX_ENTRIES: usize = 2000;
const MAX_TEXT: usize = 600;
const MIN_MARKER: usize = 8;
const MIN_KEY_COMMENT: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownBad {
    pub serial: u64,
    pub updated: String,
    pub incidents: Vec<Incident>,
    /// Entries left out because they broke the exact-match rules.
    pub dropped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incident {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub source: String,
    pub remediation: String,
    pub extensions: Vec<BadExtension>,
    /// Paths relative to home.
    pub files: Vec<String>,
    pub ssh_key_comments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadExtension {
    /// Lowercase `publisher.name`.
    pub id: String,
    /// `None`: every release is affected.
    pub versions: Option<Vec<String>>,
    /// Strings that must all appear in the entry script; empty means id and version are enough.
    pub markers: Vec<String>,
}

/// Which list a scan used, for the report header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListStatus {
    /// A signed download newer than the built-in copy.
    Downloaded,
    /// The built-in copy is current: the download was the same or older.
    BuiltInCurrent,
    /// --offline: nothing was fetched.
    BuiltInOffline,
    /// The download failed or was rejected; the reason is shown.
    BuiltInFallback(String),
}

impl KnownBad {
    /// The header fragment, e.g. "list 2026-11-02" or "list 2026-11-02 (built in)".
    pub fn label(&self, status: &ListStatus) -> String {
        let base = format!("list {}", self.updated);
        match status {
            ListStatus::Downloaded | ListStatus::BuiltInCurrent => base,
            ListStatus::BuiltInOffline => format!("{base} (built in)"),
            ListStatus::BuiltInFallback(why) => format!("{base} (built in: {why})"),
        }
    }
}

#[derive(Deserialize)]
struct RawList {
    schema: u32,
    serial: u64,
    updated: String,
    #[serde(default)]
    incidents: Vec<RawIncident>,
}

#[derive(Deserialize)]
struct RawIncident {
    id: String,
    name: String,
    summary: String,
    source: String,
    #[serde(default)]
    remediation: String,
    #[serde(default)]
    extensions: Vec<RawExtension>,
    #[serde(default)]
    files: Vec<String>,
    #[serde(default)]
    ssh_key_comments: Vec<String>,
}

#[derive(Deserialize)]
struct RawExtension {
    id: String,
    versions: Option<Vec<String>>,
    #[serde(default)]
    markers: Vec<String>,
}

/// Text shown in the terminal: bounded, and no control characters (no escape codes).
fn shown_text_ok(t: &str) -> bool {
    !t.trim().is_empty() && t.chars().count() <= MAX_TEXT && !t.chars().any(char::is_control)
}

fn slug_ok(t: &str, max: usize) -> bool {
    !t.is_empty()
        && t.len() <= max
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn extension_ok(e: &RawExtension) -> bool {
    let id = e.id.to_ascii_lowercase();
    let id_ok = id.len() <= 200
        && id
            .split_once('.')
            .is_some_and(|(p, n)| !p.is_empty() && !n.is_empty())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    let versions_ok = e.versions.as_ref().is_none_or(|vs| {
        !vs.is_empty()
            && vs.iter().all(|v| {
                !v.is_empty()
                    && v.len() <= 50
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            })
    });
    let markers_ok = e.markers.iter().all(|m| {
        m.chars().count() >= MIN_MARKER && m.len() <= 200 && !m.chars().any(char::is_control)
    });
    id_ok && versions_ok && markers_ok
}

fn file_ok(p: &str) -> bool {
    p.len() <= 300 && !p.chars().any(char::is_control) && is_safe_relative(p)
}

fn key_comment_ok(c: &str) -> bool {
    c.chars().count() >= MIN_KEY_COMMENT
        && c.len() <= 200
        && !c.chars().any(|ch| ch.is_whitespace() || ch.is_control())
}

/// Parses and validates a list. Whole-list problems are errors; a bad entry is dropped.
pub fn parse(json: &str) -> Result<KnownBad, String> {
    let raw: RawList =
        serde_json::from_str(json).map_err(|e| format!("not a known-bad list: {e}"))?;
    if raw.schema != 1 {
        return Err(format!("unsupported list schema {}", raw.schema));
    }
    let entries: usize = raw
        .incidents
        .iter()
        .map(|i| i.extensions.len() + i.files.len() + i.ssh_key_comments.len())
        .sum();
    if entries > MAX_ENTRIES {
        return Err(format!(
            "list has {entries} entries; the limit is {MAX_ENTRIES}"
        ));
    }
    if !shown_text_ok(&raw.updated) || raw.updated.len() > 20 {
        return Err("list has an invalid date".into());
    }

    let mut dropped = 0;
    let mut incidents = Vec::new();
    for r in raw.incidents {
        let needs_remediation = !r.files.is_empty() || !r.ssh_key_comments.is_empty();
        let header_ok = slug_ok(&r.id, 60)
            && shown_text_ok(&r.name)
            && r.name.chars().count() <= 80
            && shown_text_ok(&r.summary)
            && r.source.starts_with("https://")
            && r.source.len() <= 500
            && !r
                .source
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            && (if needs_remediation {
                shown_text_ok(&r.remediation)
            } else {
                r.remediation.is_empty() || shown_text_ok(&r.remediation)
            });
        if !header_ok {
            dropped += 1;
            continue;
        }
        let before = r.extensions.len() + r.files.len() + r.ssh_key_comments.len();
        let extensions: Vec<BadExtension> = r
            .extensions
            .into_iter()
            .filter(extension_ok)
            .map(|e| BadExtension {
                id: e.id.to_ascii_lowercase(),
                versions: e.versions,
                markers: e.markers,
            })
            .collect();
        let files: Vec<String> = r.files.into_iter().filter(|p| file_ok(p)).collect();
        let ssh_key_comments: Vec<String> = r
            .ssh_key_comments
            .into_iter()
            .filter(|c| key_comment_ok(c))
            .collect();
        dropped += before - (extensions.len() + files.len() + ssh_key_comments.len());
        incidents.push(Incident {
            id: r.id,
            name: r.name,
            summary: r.summary,
            source: r.source,
            remediation: r.remediation,
            extensions,
            files,
            ssh_key_comments,
        });
    }
    Ok(KnownBad {
        serial: raw.serial,
        updated: raw.updated,
        incidents,
        dropped,
    })
}

/// Checks the minisign signature with `public_key`, then parses.
pub fn verify(json: &[u8], signature: &str, public_key: &str) -> Result<KnownBad, String> {
    let key = minisign_verify::PublicKey::decode(public_key)
        .map_err(|_| "signature check failed: no valid public key".to_string())?;
    let sig = minisign_verify::Signature::decode(signature)
        .map_err(|_| "signature check failed: unreadable signature".to_string())?;
    key.verify(json, &sig, false)
        .map_err(|_| "signature check failed".to_string())?;
    let text = std::str::from_utf8(json).map_err(|_| "list is not UTF-8".to_string())?;
    parse(text)
}

/// Picks the list to use from the built-in copy and a download (body, signature).
pub fn choose(
    builtin: &KnownBad,
    download: Result<(Vec<u8>, String), String>,
    public_key: &str,
) -> (KnownBad, ListStatus) {
    let (body, sig) = match download {
        Ok(d) => d,
        // curl's own message is too long for the header; the reason is enough.
        Err(_) => {
            return (
                builtin.clone(),
                ListStatus::BuiltInFallback("download failed".into()),
            )
        }
    };
    match verify(&body, &sig, public_key) {
        // An older signed list never replaces the built-in one, so a replay can't drop entries.
        Ok(list) if list.serial > builtin.serial => (list, ListStatus::Downloaded),
        Ok(_) => (builtin.clone(), ListStatus::BuiltInCurrent),
        Err(e) => (builtin.clone(), ListStatus::BuiltInFallback(e)),
    }
}

/// The list compiled into this binary.
pub fn builtin() -> &'static KnownBad {
    static B: OnceLock<KnownBad> = OnceLock::new();
    B.get_or_init(|| parse(BUILTIN_JSON).expect("built-in known-bad list is valid"))
}

static ACTIVE: OnceLock<KnownBad> = OnceLock::new();

/// The list scanners use: the one `set_active` chose, else the built-in copy.
pub fn active() -> &'static KnownBad {
    ACTIVE.get().unwrap_or_else(builtin)
}

/// Sets the list for this run; only the first call has an effect.
pub fn set_active(list: KnownBad) {
    let _ = ACTIVE.set(list);
}

/// Fetches the list and its signature with the system curl, 10 s each. A plain GET:
/// nothing about this Mac is sent.
pub fn fetch_with_curl() -> Result<(Vec<u8>, String), String> {
    let get = |url: &str| -> Result<Vec<u8>, String> {
        let out = Command::new("/usr/bin/curl")
            .args(["-sS", "--fail", "--max-time", "10", url])
            .output()
            .map_err(|e| format!("could not start curl: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(out.stdout)
    };
    let body = get(LIST_URL)?;
    let sig = get(&format!("{LIST_URL}.minisig"))?;
    Ok((body, String::from_utf8_lossy(&sig).into_owned()))
}

/// Loads the list for a run: built-in when offline, else a verified download if newer.
pub fn load(offline: bool) -> (KnownBad, ListStatus) {
    if offline {
        return (builtin().clone(), ListStatus::BuiltInOffline);
    }
    choose(builtin(), fetch_with_curl(), PUBLIC_KEY)
}

fn is_safe_relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUB: &str = include_str!("known_bad_fixtures/test.pub");
    const NEWER: &str = include_str!("known_bad_fixtures/newer.json");
    const NEWER_SIG: &str = include_str!("known_bad_fixtures/newer.json.minisig");
    const OLDER: &str = include_str!("known_bad_fixtures/older.json");
    const OLDER_SIG: &str = include_str!("known_bad_fixtures/older.json.minisig");

    fn list(incidents: &str) -> String {
        format!(
            r#"{{"schema":1,"serial":2026110201,"updated":"2026-11-02","incidents":[{incidents}]}}"#
        )
    }

    fn incident(extra: &str) -> String {
        format!(
            r#"{{"id":"x-incident","name":"X","summary":"Something bad.","source":"https://example.com/a","remediation":"Remove it."{extra}}}"#
        )
    }

    #[test]
    fn test_owner_public_key_is_present() {
        // Release gate: the scanner must ship with the owner's real key.
        assert!(
            minisign_verify::PublicKey::decode(PUBLIC_KEY).is_ok(),
            "known-bad/minisign.pub must hold the owner's minisign public key"
        );
    }

    #[test]
    fn test_builtin_list_parses_with_nothing_dropped() {
        let b = parse(BUILTIN_JSON).unwrap();
        assert_eq!(b.dropped, 0);
        assert!(b.incidents.iter().any(|i| i.id == "claude-code-extension"));
        let cc = b
            .incidents
            .iter()
            .find(|i| i.id == "claude-code-extension")
            .unwrap();
        assert_eq!(cc.ssh_key_comments, vec!["svc-telemetry"]);
        assert_eq!(cc.extensions[0].markers.len(), 2);
        let glass = b.incidents.iter().find(|i| i.id == "glassworm").unwrap();
        assert_eq!(
            glass.extensions[0].versions, None,
            "no versions means every release"
        );
    }

    #[test]
    fn test_parse_rejects_wrong_schema_and_too_many_entries() {
        assert!(parse(r#"{"schema":2,"serial":1,"updated":"x","incidents":[]}"#).is_err());
        assert!(parse("not json").is_err());
        let files: Vec<String> = (0..2001).map(|n| format!("\".f/{n}\"")).collect();
        let big = list(&incident(&format!(r#","files":[{}]"#, files.join(","))));
        assert!(parse(&big).unwrap_err().contains("2000"));
    }

    #[test]
    fn test_parse_drops_entries_that_could_match_broadly() {
        let l = list(&incident(
            r#","files":["/etc/passwd","../x","", ".config/.ok"],
               "extensions":[{"id":"noperiod"},{"id":"a.b","versions":[]},{"id":"a.b","markers":["short"]},{"id":"Good.Ext","versions":["1.0.0"]}],
               "ssh_key_comments":["ab","has space","long-enough"]"#,
        ));
        let k = parse(&l).unwrap();
        let i = &k.incidents[0];
        assert_eq!(i.files, vec![".config/.ok"]);
        assert_eq!(i.extensions.len(), 1);
        assert_eq!(i.extensions[0].id, "good.ext");
        assert_eq!(i.ssh_key_comments, vec!["long-enough"]);
        assert_eq!(k.dropped, 8);
    }

    #[test]
    fn test_parse_drops_incidents_with_bad_text_or_source() {
        // Terminal escape codes in shown text, and a non-https source.
        let esc = r#"{"id":"esc","name":"E\u001b[31m","summary":"s","source":"https://example.com","remediation":"r","files":[".a/b"]}"#;
        let http = r#"{"id":"http","name":"H","summary":"s","source":"http://example.com","remediation":"r","files":[".a/b"]}"#;
        let ok = incident(r#","files":[".a/b"]"#);
        let k = parse(&list(&format!("{esc},{http},{ok}"))).unwrap();
        assert_eq!(k.incidents.len(), 1);
        assert_eq!(k.incidents[0].id, "x-incident");
        assert_eq!(k.dropped, 2);
    }

    #[test]
    fn test_verify_accepts_the_signed_list_and_rejects_tampering_and_other_keys() {
        assert_eq!(
            verify(NEWER.as_bytes(), NEWER_SIG, TEST_PUB)
                .unwrap()
                .serial,
            2099010101
        );
        let tampered = NEWER.replace("fixture-incident", "fixture-incidenu");
        assert!(verify(tampered.as_bytes(), NEWER_SIG, TEST_PUB).is_err());
        assert!(verify(NEWER.as_bytes(), OLDER_SIG, TEST_PUB).is_err());
        assert!(
            verify(NEWER.as_bytes(), NEWER_SIG, PUBLIC_KEY).is_err(),
            "test key is not the owner key"
        );
        assert!(verify(NEWER.as_bytes(), "garbage", TEST_PUB).is_err());
    }

    #[test]
    fn test_choose_uses_a_newer_signed_download() {
        let b = parse(BUILTIN_JSON).unwrap();
        let (k, s) = choose(
            &b,
            Ok((NEWER.as_bytes().to_vec(), NEWER_SIG.into())),
            TEST_PUB,
        );
        assert_eq!(s, ListStatus::Downloaded);
        assert_eq!(k.serial, 2099010101);
    }

    #[test]
    fn test_choose_keeps_builtin_for_older_unsigned_or_failed_downloads() {
        let b = parse(BUILTIN_JSON).unwrap();
        let (k, s) = choose(
            &b,
            Ok((OLDER.as_bytes().to_vec(), OLDER_SIG.into())),
            TEST_PUB,
        );
        assert_eq!((k.serial, s), (b.serial, ListStatus::BuiltInCurrent));

        let tampered = NEWER.replace("2099-01-01", "2099-01-02");
        let (k, s) = choose(&b, Ok((tampered.into_bytes(), NEWER_SIG.into())), TEST_PUB);
        assert_eq!(k.serial, b.serial);
        assert!(
            matches!(&s, ListStatus::BuiltInFallback(r) if r.contains("signature")),
            "{s:?}"
        );

        let (_, s) = choose(&b, Err("timed out".into()), TEST_PUB);
        assert!(
            matches!(&s, ListStatus::BuiltInFallback(r) if r.contains("download failed")),
            "{s:?}"
        );
    }

    #[test]
    fn test_label_says_which_list_and_why() {
        let b = parse(BUILTIN_JSON).unwrap();
        assert_eq!(b.label(&ListStatus::Downloaded), "list 2026-11-02");
        assert_eq!(b.label(&ListStatus::BuiltInCurrent), "list 2026-11-02");
        assert_eq!(
            b.label(&ListStatus::BuiltInOffline),
            "list 2026-11-02 (built in)"
        );
        assert_eq!(
            b.label(&ListStatus::BuiltInFallback(
                "signature check failed".into()
            )),
            "list 2026-11-02 (built in: signature check failed)"
        );
    }
}
