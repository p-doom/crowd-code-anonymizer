//! JSON report generation

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::redactor::FileRedactionResult;

/// Summary statistics for the report
#[derive(Debug, Serialize)]
struct ReportSummary {
    total_files: usize,
    total_rows: usize,
    total_redactions: usize,
    files_with_redactions: usize,
}

/// Full report structure
#[derive(Debug, Serialize)]
struct Report {
    summary: ReportSummary,
    files: Vec<FileRedactionResult>,
}

/// Write a JSON report of all redaction results
pub fn write_report(results: &[FileRedactionResult], path: &Path) -> Result<()> {
    let summary = ReportSummary {
        total_files: results.len(),
        total_rows: results.iter().map(|r| r.total_rows).sum(),
        total_redactions: results.iter().map(|r| r.redactions.len()).sum(),
        files_with_redactions: results.iter().filter(|r| !r.redactions.is_empty()).count(),
    };

    let report = Report {
        summary,
        files: results.to_vec(),
    };

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(path)
        .with_context(|| format!("Failed to create report: {}", path.display()))?;
    let writer = BufWriter::new(file);

    serde_json::to_writer_pretty(writer, &report)
        .with_context(|| "Failed to write JSON report")?;

    Ok(())
}

/// Print summary to stderr
pub fn print_summary(results: &[FileRedactionResult]) {
    let total_rows: usize = results.iter().map(|r| r.total_rows).sum();
    let total_redactions: usize = results.iter().map(|r| r.redactions.len()).sum();
    let files_with_redactions = results.iter().filter(|r| !r.redactions.is_empty()).count();

    eprintln!("\n=== Summary ===");
    eprintln!("Files processed: {}", results.len());
    eprintln!("Files with redactions: {}", files_with_redactions);
    eprintln!("Total rows: {}", total_rows);
    eprintln!("Total redactions: {}", total_redactions);

    // Count by label
    let mut by_label: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for result in results {
        for redaction in &result.redactions {
            *by_label.entry(&redaction.label).or_default() += 1;
        }
    }

    if !by_label.is_empty() {
        eprintln!("\nRedactions by type:");
        let mut labels: Vec<_> = by_label.into_iter().collect();
        labels.sort_by(|a, b| b.1.cmp(&a.1));
        for (label, count) in labels {
            eprintln!("  {}: {}", label, count);
        }
    }
}

