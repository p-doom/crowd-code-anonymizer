//! CSV Anonymization Library
//!
//! Fast, regex-based detection and redaction of sensitive data in CSV files.

pub mod csv_parser;
pub mod detectors;
pub mod redactor;
pub mod report;
pub mod review;

pub use csv_parser::{CSVRow, find_csv_files, parse_csv_file, write_csv_file};
pub use detectors::{Finding, Detector};
pub use redactor::{Redaction, Redactor, FileRedactionResult};
pub use report::write_report;

