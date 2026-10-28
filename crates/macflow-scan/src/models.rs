use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    #[serde(alias = "ai_agent_setup")]
    AgentAudit,
    Security,
    Garbage,
}

impl Category {
    #[allow(non_upper_case_globals)]
    pub const AiAgentSetup: Category = Category::AgentAudit;
    pub const ALL: [Category; 3] = [Category::AgentAudit, Category::Security, Category::Garbage];

    pub fn all() -> &'static [Category] {
        &Self::ALL
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::AgentAudit => "AI agent setup",
            Self::Security => "Security",
            Self::Garbage => "Garbage",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryCoverage {
    Checked,
    PartiallyChecked,
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum InspectionStatus {
    Inspected {
        inspected_scope: String,
    },
    Skipped {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    UnparseableData {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        error: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inspection {
    pub category: Category,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_category: Option<String>,
    pub status: InspectionStatus,
}

impl Inspection {
    pub fn inspected(category: Category, sub: Option<&str>, scope: impl Into<String>) -> Self {
        Self {
            category,
            sub_category: sub.map(str::to_string),
            status: InspectionStatus::Inspected {
                inspected_scope: scope.into(),
            },
        }
    }

    pub fn skipped(category: Category, sub: Option<&str>, reason: Option<&str>) -> Self {
        Self {
            category,
            sub_category: sub.map(str::to_string),
            status: InspectionStatus::Skipped {
                reason: reason.map(str::to_string),
            },
        }
    }

    pub fn unparseable(
        category: Category,
        sub: Option<&str>,
        p: Option<&str>,
        e: impl Into<String>,
    ) -> Self {
        Self {
            category,
            sub_category: sub.map(str::to_string),
            status: InspectionStatus::UnparseableData {
                path: p.map(str::to_string),
                error: e.into(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub category: Category,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub severity: Severity,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        category: Category,
        severity: Severity,
        desc: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            category,
            sub_category: None,
            scope: None,
            severity,
            description: desc.into(),
            file_path: None,
            line_number: None,
            remediation: None,
        }
    }

    pub fn with_sub_category(mut self, sub: impl Into<String>) -> Self {
        self.sub_category = Some(sub.into());
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn with_location(mut self, path: impl Into<String>, line: Option<usize>) -> Self {
        self.file_path = Some(path.into());
        self.line_number = line;
        self
    }

    pub fn with_remediation(mut self, rem: impl Into<String>) -> Self {
        self.remediation = Some(rem.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanContext {
    pub root_paths: Vec<PathBuf>,
    pub selected_categories: Vec<Category>,
    pub offline: bool,
}

impl Default for ScanContext {
    fn default() -> Self {
        Self {
            root_paths: Vec::new(),
            selected_categories: Category::all().to_vec(),
            offline: false,
        }
    }
}

impl ScanContext {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.root_paths = roots;
        self
    }
    pub fn with_categories(mut self, cats: Vec<Category>) -> Self {
        self.selected_categories = cats;
        self
    }
    pub fn with_offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }
    pub fn is_category_selected(&self, cat: Category) -> bool {
        self.selected_categories.contains(&cat)
    }
}

fn default_schema_version() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub findings: Vec<Finding>,
    pub inspections: Vec<Inspection>,
    pub timestamp: String,
}

impl ScanResult {
    pub fn new(
        findings: Vec<Finding>,
        inspections: Vec<Inspection>,
        ts: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: default_schema_version(),
            findings,
            inspections,
            timestamp: ts.into(),
        }
    }

    pub fn empty(ts: impl Into<String>) -> Self {
        Self::new(Vec::new(), Vec::new(), ts)
    }

    pub fn category_coverage(&self, cat: Category) -> CategoryCoverage {
        let insp = self.inspections_for_category(cat);
        let checked = insp
            .iter()
            .filter(|i| matches!(i.status, InspectionStatus::Inspected { .. }))
            .count();
        match (insp.is_empty(), checked) {
            (true, _) | (_, 0) => CategoryCoverage::NotChecked,
            (_, c) if c == insp.len() => CategoryCoverage::Checked,
            _ => CategoryCoverage::PartiallyChecked,
        }
    }

    pub fn is_category_checked(&self, cat: Category) -> bool {
        self.category_coverage(cat) == CategoryCoverage::Checked
    }

    pub fn is_category_partially_checked(&self, cat: Category) -> bool {
        self.category_coverage(cat) == CategoryCoverage::PartiallyChecked
    }

    pub fn is_category_not_checked(&self, cat: Category) -> bool {
        self.category_coverage(cat) == CategoryCoverage::NotChecked
    }

    /// Alias for backwards compatibility. Prefer [`is_category_not_checked`].
    pub fn is_category_skipped(&self, cat: Category) -> bool {
        self.is_category_not_checked(cat)
    }

    pub fn has_unparseable_data(&self, cat: Category) -> bool {
        self.inspections.iter().any(|i| {
            i.category == cat && matches!(i.status, InspectionStatus::UnparseableData { .. })
        })
    }

    pub fn findings_for_category(&self, cat: Category) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.category == cat).collect()
    }

    pub fn inspections_for_category(&self, cat: Category) -> Vec<&Inspection> {
        self.inspections
            .iter()
            .filter(|i| i.category == cat)
            .collect()
    }

    pub fn count_by_severity(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_models_serde_and_display() {
        assert!(Severity::Critical > Severity::High && Severity::High > Severity::Medium);
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        let s = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(
            serde_json::from_str::<Severity>(&s).unwrap(),
            Severity::Critical
        );
        assert_eq!(Category::AgentAudit.display_name(), "AI agent setup");
        assert_eq!(Category::AiAgentSetup, Category::AgentAudit);
        assert_eq!(
            serde_json::to_string(&Category::AgentAudit).unwrap(),
            "\"agent_audit\""
        );
        assert_eq!(
            serde_json::from_str::<Category>("\"ai_agent_setup\"").unwrap(),
            Category::AgentAudit
        );

        let insp = Inspection::inspected(Category::AgentAudit, Some("hooks"), "hooks");
        let j = serde_json::to_string(&insp).unwrap();
        assert!(
            j.contains("\"status\":\"inspected\"") && j.contains("\"inspected_scope\":\"hooks\"")
        );
        assert_eq!(serde_json::from_str::<Inspection>(&j).unwrap(), insp);

        let unp =
            Inspection::unparseable(Category::AgentAudit, Some("tasks"), Some("t.json"), "err");
        let uj = serde_json::to_string(&unp).unwrap();
        assert!(uj.contains("\"status\":\"unparseable_data\"") && uj.contains("\"error\":\"err\""));

        let f = Finding::new(
            "a1",
            "Unpinned",
            Category::AgentAudit,
            Severity::High,
            "Desc",
        )
        .with_sub_category("mcp")
        .with_scope("user")
        .with_location("~/.claude.json", Some(12))
        .with_remediation("Pin");
        let f_json = serde_json::to_string(&f).unwrap();
        assert!(f_json.contains("\"scope\":\"user\""));
        assert_eq!(serde_json::from_str::<Finding>(&f_json).unwrap(), f);

        let ctx = ScanContext::new()
            .with_roots(vec![PathBuf::from("/test")])
            .with_categories(vec![Category::AgentAudit])
            .with_offline(true);
        assert!(
            ctx.offline
                && ctx.is_category_selected(Category::AgentAudit)
                && !ctx.is_category_selected(Category::Security)
        );
    }

    #[test]
    fn test_scan_result_operations_and_coverage() {
        let f1 = Finding::new("ai-1", "F1", Category::AgentAudit, Severity::Critical, "D1");
        let f2 = Finding::new("sec-1", "F2", Category::Security, Severity::High, "D2");
        let insp = vec![
            Inspection::inspected(Category::AgentAudit, None, "inspected hooks"),
            Inspection::skipped(Category::Garbage, None, Some("disabled")),
            Inspection::unparseable(Category::Security, Some("pkg"), Some("pkg.json"), "error"),
        ];
        let res = ScanResult::new(vec![f1, f2], insp, "2026-10-20T00:00:00Z");
        assert_eq!(res.findings_for_category(Category::AgentAudit).len(), 1);
        assert!(
            res.count_by_severity(Severity::Critical) == 1
                && res.count_by_severity(Severity::Low) == 0
        );
        assert!(
            res.is_category_checked(Category::AgentAudit)
                && res.category_coverage(Category::AgentAudit) == CategoryCoverage::Checked
        );
        assert!(
            res.is_category_not_checked(Category::Garbage)
                && res.is_category_skipped(Category::Garbage)
                && res.category_coverage(Category::Garbage) == CategoryCoverage::NotChecked
        );
        assert!(
            res.has_unparseable_data(Category::Security)
                && res.is_category_not_checked(Category::Security)
                && res.category_coverage(Category::Security) == CategoryCoverage::NotChecked
        );

        let partial = ScanResult::new(
            vec![],
            vec![
                Inspection::inspected(Category::AgentAudit, Some("h"), "1 file"),
                Inspection::unparseable(Category::AgentAudit, Some("t"), Some("t.json"), "err"),
            ],
            "2026-10-20T00:00:00Z",
        );
        assert!(
            !partial.is_category_checked(Category::AgentAudit)
                && partial.is_category_partially_checked(Category::AgentAudit)
        );
        assert_eq!(
            partial.category_coverage(Category::AgentAudit),
            CategoryCoverage::PartiallyChecked
        );

        let mixed = ScanResult::new(
            vec![],
            vec![
                Inspection::skipped(Category::Security, Some("p1"), Some("disabled")),
                Inspection::unparseable(
                    Category::Security,
                    Some("p2"),
                    Some("p.json"),
                    "syntax err",
                ),
            ],
            "2026-10-20T00:00:00Z",
        );
        assert_eq!(
            mixed.category_coverage(Category::Security),
            CategoryCoverage::NotChecked
        );
        assert!(mixed.is_category_not_checked(Category::Security));
        assert!(mixed.is_category_skipped(Category::Security));
    }
}
