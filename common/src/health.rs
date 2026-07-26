//! Local password-health analysis (never leaves the unlocked vault / client).

use crate::types::{Entry, EntryId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthKind {
    Empty,
    TooShort,
    WeakCharset,
    Reused,
    CommonPassword,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthIssue {
    pub kind: HealthKind,
    pub entry_id: EntryId,
    pub entry_name: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthReport {
    pub total_entries: u32,
    pub issue_count: u32,
    /// 0–100, higher is healthier.
    pub score: u8,
    pub issues: Vec<HealthIssue>,
    pub reused_groups: u32,
    pub empty_count: u32,
    pub weak_count: u32,
}

/// Small built-in denylist (not a substitute for breach DB).
const COMMON: &[&str] = &[
    "password",
    "password1",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "login",
    "passw0rd",
    "hunter2",
];

pub fn analyze_entries<'a, I>(entries: I) -> HealthReport
where
    I: IntoIterator<Item = &'a Entry>,
{
    let entries: Vec<&Entry> = entries.into_iter().collect();
    let total = entries.len() as u32;
    let mut issues = Vec::new();
    let mut empty_count = 0u32;
    let mut weak_count = 0u32;

    // Group by password for reuse detection (skip empty).
    let mut by_pw: HashMap<&str, Vec<&Entry>> = HashMap::new();
    for e in &entries {
        if e.password.is_empty() {
            empty_count += 1;
            issues.push(HealthIssue {
                kind: HealthKind::Empty,
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                detail: "no password set".into(),
            });
            continue;
        }
        by_pw.entry(e.password.as_str()).or_default().push(*e);

        if e.password.len() < 10 {
            weak_count += 1;
            issues.push(HealthIssue {
                kind: HealthKind::TooShort,
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                detail: format!("only {} characters (recommend 12+)", e.password.len()),
            });
        } else if !has_mixed_charset(&e.password) {
            weak_count += 1;
            issues.push(HealthIssue {
                kind: HealthKind::WeakCharset,
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                detail: "uses only one character class (letters/digits/symbols)".into(),
            });
        }

        let lower = e.password.to_ascii_lowercase();
        if COMMON.iter().any(|c| *c == lower.as_str()) {
            weak_count += 1;
            issues.push(HealthIssue {
                kind: HealthKind::CommonPassword,
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                detail: "matches a common password list".into(),
            });
        }
    }

    let mut reused_groups = 0u32;
    for (_pw, group) in by_pw {
        if group.len() < 2 {
            continue;
        }
        reused_groups += 1;
        let names: Vec<&str> = group.iter().map(|e| e.name.as_str()).collect();
        for e in group {
            issues.push(HealthIssue {
                kind: HealthKind::Reused,
                entry_id: e.id.clone(),
                entry_name: e.name.clone(),
                detail: format!("same password as: {}", names.join(", ")),
            });
        }
    }

    // Score: start 100, deduct per issue type (capped).
    let mut score: i32 = 100;
    if total == 0 {
        score = 100;
    } else {
        score -= (empty_count as i32) * 15;
        score -= (weak_count as i32) * 8;
        score -= (reused_groups as i32) * 12;
        // mild penalty if many issues relative to vault size
        let ratio = issues.len() as i32 * 100 / (total as i32).max(1);
        if ratio > 50 {
            score -= 10;
        }
    }
    let score = score.clamp(0, 100) as u8;

    HealthReport {
        total_entries: total,
        issue_count: issues.len() as u32,
        score,
        issues,
        reused_groups,
        empty_count,
        weak_count,
    }
}

fn has_mixed_charset(pw: &str) -> bool {
    let mut classes = 0u8;
    if pw.chars().any(|c| c.is_ascii_alphabetic()) {
        classes += 1;
    }
    if pw.chars().any(|c| c.is_ascii_digit()) {
        classes += 1;
    }
    if pw.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes += 1;
    }
    classes >= 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Entry;

    #[test]
    fn detects_reuse_and_empty() {
        let mut a = Entry::new("1", "A");
        a.password = "same-pass-here!".into();
        let mut b = Entry::new("2", "B");
        b.password = "same-pass-here!".into();
        let mut c = Entry::new("3", "C");
        c.password = "".into();
        let mut d = Entry::new("4", "D");
        d.password = "password".into();

        let report = analyze_entries([&a, &b, &c, &d]);
        assert!(report.empty_count >= 1);
        assert!(report.reused_groups >= 1);
        assert!(report.issues.iter().any(|i| i.kind == HealthKind::CommonPassword));
        assert!(report.score < 100);
    }
}
