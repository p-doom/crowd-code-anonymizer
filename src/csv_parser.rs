//! CSV parsing for source.csv files
//!
//! Handles reading and writing CSV files with the expected format:
//! row_id, type, text

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

/// A single row from a source.csv file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CSVRow {
    /// Row index in the CSV file
    pub row_id: usize,
    /// Type of content (e.g., "tab", "terminal_output")
    #[serde(rename = "type")]
    pub row_type: String,
    /// The text content to scan for sensitive data
    pub text: String,
}

/// Find all source.csv files in a directory
pub fn find_csv_files(dir: &Path, recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if recursive {
        for entry in WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if is_source_csv(path) {
                files.push(path.to_path_buf());
            }
        }
    } else {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if is_source_csv(&path) {
                files.push(path);
            }
        }
    }

    // Sort for deterministic ordering
    files.sort();

    Ok(files)
}

/// Check if a path is a source.csv file (excluding already anonymized files)
fn is_source_csv(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Must be a CSV file
    if !file_name.ends_with(".csv") {
        return false;
    }

    // Exclude already anonymized files
    if file_name.contains(".anonymized.") {
        return false;
    }

    true
}

/// Parse a source.csv file into rows
pub fn parse_csv_file(path: &Path) -> Result<Vec<CSVRow>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open: {}", path.display()))?;
    let reader = BufReader::new(file);
    
    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(reader);

    let headers = csv_reader.headers()?.clone();
    
    // Find column indices
    let row_id_idx = find_column(&headers, &["row_id", "id", "index"]);
    let type_idx = find_column(&headers, &["type", "row_type", "content_type"]);
    let text_idx = find_column(&headers, &["text", "content", "value"]);

    let mut rows = Vec::new();

    for (i, result) in csv_reader.records().enumerate() {
        let record = result.with_context(|| format!("Error reading row {}", i + 1))?;
        
        let row_id = row_id_idx
            .and_then(|idx| record.get(idx))
            .and_then(|s| s.parse().ok())
            .unwrap_or(i);

        let row_type = type_idx
            .and_then(|idx| record.get(idx))
            .unwrap_or("unknown")
            .to_string();

        let text = text_idx
            .and_then(|idx| record.get(idx))
            .unwrap_or("")
            .to_string();

        rows.push(CSVRow {
            row_id,
            row_type,
            text,
        });
    }

    Ok(rows)
}

/// Find a column by trying multiple possible names
fn find_column(headers: &csv::StringRecord, names: &[&str]) -> Option<usize> {
    for name in names {
        for (i, header) in headers.iter().enumerate() {
            if header.eq_ignore_ascii_case(name) {
                return Some(i);
            }
        }
    }
    None
}

/// Write a CSV file with redactions applied
pub fn write_csv_file(
    rows: &[CSVRow],
    redactions: &[crate::Redaction],
    output_path: &Path,
) -> Result<()> {
    // Create parent directories if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(output_path)
        .with_context(|| format!("Failed to create: {}", output_path.display()))?;
    let writer = BufWriter::new(file);

    let mut csv_writer = csv::Writer::from_writer(writer);

    // Write header
    csv_writer.write_record(["row_id", "type", "text"])?;

    // Apply redactions to each row
    for row in rows {
        let redacted_text = apply_redactions(&row.text, row.row_id, redactions);
        csv_writer.write_record([
            &row.row_id.to_string(),
            &row.row_type,
            &redacted_text,
        ])?;
    }

    csv_writer.flush()?;

    Ok(())
}

/// Apply redactions to text for a specific row
fn apply_redactions(text: &str, row_id: usize, redactions: &[crate::Redaction]) -> String {
    // Filter redactions for this row
    let mut row_redactions: Vec<_> = redactions
        .iter()
        .filter(|r| r.row_id == row_id && r.accepted)
        .collect();

    if row_redactions.is_empty() {
        return text.to_string();
    }

    // Sort by start position (descending) to apply from end to start
    row_redactions.sort_by(|a, b| b.start.cmp(&a.start));

    let mut result = text.to_string();
    for redaction in row_redactions {
        if redaction.end <= result.len() {
            let replacement = format!("[{}]", redaction.label);
            result.replace_range(redaction.start..redaction.end, &replacement);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_source_csv() {
        assert!(is_source_csv(Path::new("source.csv")));
        assert!(is_source_csv(Path::new("data.csv")));
        assert!(!is_source_csv(Path::new("source.anonymized.csv")));
        assert!(!is_source_csv(Path::new("data.txt")));
    }
}

