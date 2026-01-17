//! Redaction logic: combines findings from all detectors
//!
//! Handles merging overlapping findings and applying redactions to text.

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::csv_parser::CSVRow;
use crate::detectors::{
    Detector, Finding,
    PiiDetector, SecretsDetector, NameDetector, CustomDetector, EntropyDetector,
};

/// A redaction to apply to text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    /// Row ID in the CSV
    pub row_id: usize,
    /// Start position in text (byte offset)
    pub start: usize,
    /// End position in text (byte offset)
    pub end: usize,
    /// Original text that was detected
    pub original_text: String,
    /// Label for the redaction (e.g., "EMAIL", "PHONE")
    pub label: String,
    /// Source detector (e.g., "pii", "secrets", "names")
    pub source: String,
    /// Whether this redaction was accepted (for review mode)
    #[serde(default = "default_true")]
    pub accepted: bool,
    /// Line number within the text (1-indexed)
    pub line: usize,
    /// Column number within the line (1-indexed)
    pub col: usize,
}

fn default_true() -> bool {
    true
}

/// Result of redacting a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRedactionResult {
    /// Path to the input file
    pub input_path: PathBuf,
    /// Total rows processed
    pub total_rows: usize,
    /// Rows that had redactions
    pub rows_with_redactions: usize,
    /// All redactions found
    pub redactions: Vec<Redaction>,
}

impl Default for FileRedactionResult {
    fn default() -> Self {
        Self {
            input_path: PathBuf::new(),
            total_rows: 0,
            rows_with_redactions: 0,
            redactions: Vec::new(),
        }
    }
}

/// Main redactor combining all detectors
pub struct Redactor {
    pii_detector: PiiDetector,
    secrets_detector: SecretsDetector,
    name_detector: NameDetector,
    custom_detector: CustomDetector,
    entropy_detector: EntropyDetector,
}

impl Redactor {
    /// Create a new redactor
    pub fn new(strict: bool, names_dir: Option<&Path>) -> Result<Self> {
        Ok(Self {
            pii_detector: PiiDetector::new(strict),
            secrets_detector: SecretsDetector::new(strict),
            name_detector: NameDetector::new(names_dir)?,
            custom_detector: CustomDetector::new(strict),
            entropy_detector: EntropyDetector::new(),
        })
    }

    /// Detect sensitive data in text and return findings
    pub fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        findings.extend(self.pii_detector.detect(text));
        findings.extend(self.secrets_detector.detect(text));
        findings.extend(self.name_detector.detect(text));
        findings.extend(self.custom_detector.detect(text));
        findings.extend(self.entropy_detector.detect(text));

        merge_findings(findings)
    }

    /// Redact all rows and return result
    pub fn redact_rows(&self, rows: &[CSVRow]) -> FileRedactionResult {
        let mut result = FileRedactionResult {
            total_rows: rows.len(),
            ..Default::default()
        };

        for row in rows {
            let findings = self.detect(&row.text);
            
            if !findings.is_empty() {
                result.rows_with_redactions += 1;
            }

            for finding in findings {
                let (line, col) = calculate_position(&row.text, finding.start);
                
                result.redactions.push(Redaction {
                    row_id: row.row_id,
                    start: finding.start,
                    end: finding.end,
                    original_text: finding.text,
                    label: finding.label,
                    source: finding.source,
                    accepted: true,
                    line,
                    col,
                });
            }
        }

        result
    }
}

/// Merge overlapping findings, preferring higher-score or more specific findings
fn merge_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    if findings.len() <= 1 {
        return findings;
    }

    findings.sort_by(|a, b| {
        a.start.cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
    });

    let mut merged = Vec::new();
    let mut current: Option<Finding> = None;

    for finding in findings {
        match &mut current {
            None => {
                current = Some(finding);
            }
            Some(curr) => {
                if finding.start < curr.end {
                    let curr_len = curr.end - curr.start;
                    let new_len = finding.end - finding.start;
                    let new_end = finding.end;
                    
                    if finding.score > curr.score || 
                       (finding.score == curr.score && new_len > curr_len) {
                        *curr = finding;
                    }
                    if new_end > curr.end {
                        curr.end = new_end;
                    }
                } else {
                    merged.push(current.take().unwrap());
                    current = Some(finding);
                }
            }
        }
    }

    if let Some(curr) = current {
        merged.push(curr);
    }

    merged
}

/// Calculate line and column number for a byte offset
fn calculate_position(text: &str, offset: usize) -> (usize, usize) {
    let prefix = &text[..offset.min(text.len())];
    let line = prefix.chars().filter(|&c| c == '\n').count() + 1;
    let last_newline = prefix.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let col = offset - last_newline + 1;
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_position() {
        let text = "Line 1\nLine 2\nLine 3";
        assert_eq!(calculate_position(text, 0), (1, 1));
        assert_eq!(calculate_position(text, 5), (1, 6));
        assert_eq!(calculate_position(text, 7), (2, 1));
        assert_eq!(calculate_position(text, 14), (3, 1));
    }

    #[test]
    fn test_merge_overlapping() {
        let findings = vec![
            Finding::new(0, 10, "test@test.com".into(), "EMAIL", "pii").with_score(0.9),
            Finding::new(5, 8, "test".into(), "WORD", "custom").with_score(0.5),
        ];

        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].label, "EMAIL");
    }

    #[test]
    fn test_merge_non_overlapping() {
        let findings = vec![
            Finding::new(0, 10, "test@test.com".into(), "EMAIL", "pii"),
            Finding::new(20, 30, "192.168.1.1".into(), "IP", "pii"),
        ];

        let merged = merge_findings(findings);
        assert_eq!(merged.len(), 2);
    }
}

