//! CSV Anonymizer CLI
//!
//! Fast, regex-based detection and redaction of sensitive data in CSV files.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;

use anonymizer::{
    find_csv_files, parse_csv_file, write_csv_file, write_report,
    Redactor, FileRedactionResult,
};
use anonymizer::review::ReviewSession;

/// Fast CSV anonymization tool for crowd-sourced software engineering traces
#[derive(Parser, Debug)]
#[command(name = "anonymize")]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or directory
    input: PathBuf,

    /// Output directory (default: same as input with .anonymized suffix)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Process directories recursively
    #[arg(short, long)]
    recursive: bool,

    /// Don't write output files, just report what would be redacted
    #[arg(long)]
    dry_run: bool,

    /// Enable strict mode with more aggressive detection
    #[arg(long)]
    strict: bool,

    /// Interactively review each redaction
    #[arg(long)]
    review: bool,

    /// Number of parallel workers (default: number of CPUs)
    #[arg(short = 'j', long, default_value_t = num_cpus())]
    workers: usize,

    /// Write JSON report to file
    #[arg(long)]
    report: Option<PathBuf>,

    /// Path to names dataset JSON file (first_names.json and last_names.json)
    #[arg(long)]
    names_dir: Option<PathBuf>,
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("Initializing anonymizer (strict={})...", args.strict);

    // Initialize redactor (loads name datasets)
    let redactor = Arc::new(Redactor::new(args.strict, args.names_dir.as_deref())?);

    // Find CSV files
    let files = if args.input.is_file() {
        vec![args.input.clone()]
    } else {
        eprintln!(
            "Processing directory: {} (recursive={})",
            args.input.display(),
            args.recursive
        );
        find_csv_files(&args.input, args.recursive)?
    };

    if files.is_empty() {
        eprintln!("No CSV files found");
        return Ok(());
    }

    let total_files = files.len();

    if args.review {
        // Review mode: sequential processing with interactive review
        run_review_mode(&args, &redactor, &files)?;
    } else {
        // Parallel processing mode
        run_parallel_mode(&args, &redactor, &files)?;
    }

    eprintln!("\nProcessed {} files", total_files);

    Ok(())
}

fn run_parallel_mode(
    args: &Args,
    redactor: &Arc<Redactor>,
    files: &[PathBuf],
) -> Result<()> {
    let total_files = files.len();
    eprintln!("Processing {} files with {} workers...", total_files, args.workers);

    // Configure thread pool
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.workers)
        .build_global()
        .ok();

    // Progress tracking
    let processed = AtomicUsize::new(0);
    let total_rows = AtomicUsize::new(0);
    let total_redactions = AtomicUsize::new(0);

    let start_time = Instant::now();

    // Progress bar
    let pb = ProgressBar::new(total_files as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{pos}/{len}] {wide_bar} {per_sec} | ETA: {eta}")
            .unwrap(),
    );

    // Process files in parallel
    let results: Vec<Result<FileRedactionResult>> = files
        .par_iter()
        .map(|file| {
            let result = process_file(file, args, redactor);
            
            if let Ok(ref res) = result {
                processed.fetch_add(1, Ordering::Relaxed);
                total_rows.fetch_add(res.total_rows, Ordering::Relaxed);
                total_redactions.fetch_add(res.redactions.len(), Ordering::Relaxed);
            }

            pb.inc(1);
            
            // Update progress message
            let current = processed.load(Ordering::Relaxed);
            let rows = total_rows.load(Ordering::Relaxed);
            let redacts = total_redactions.load(Ordering::Relaxed);
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 { current as f64 / elapsed } else { 0.0 };
            let eta = if rate > 0.0 { (total_files - current) as f64 / rate } else { 0.0 };
            
            pb.set_message(format!(
                "{} rows, {} redactions | {:.1} files/s | ETA: {:.0}m {:.0}s",
                rows, redacts, rate, eta / 60.0, eta % 60.0
            ));

            result
        })
        .collect();

    pb.finish_and_clear();

    // Collect successful results
    let successful_results: Vec<FileRedactionResult> = results
        .into_iter()
        .filter_map(|r| r.ok())
        .collect();

    // Write report if requested
    if let Some(report_path) = &args.report {
        write_report(&successful_results, report_path)?;
        eprintln!("Report written to: {}", report_path.display());
    }

    // Print summary
    let total_rows = total_rows.load(Ordering::Relaxed);
    let total_redactions = total_redactions.load(Ordering::Relaxed);
    let elapsed = start_time.elapsed();

    eprintln!(
        "\nSummary: {} rows, {} redactions in {:.2}s ({:.1} files/s)",
        total_rows,
        total_redactions,
        elapsed.as_secs_f64(),
        total_files as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}

fn run_review_mode(
    args: &Args,
    redactor: &Arc<Redactor>,
    files: &[PathBuf],
) -> Result<()> {
    let mut session = ReviewSession::new();
    let total_files = files.len();
    let mut all_results = Vec::new();

    for (i, file) in files.iter().enumerate() {
        eprintln!("═══ File {}/{}: {} ═══", i + 1, total_files, file.file_name().unwrap_or_default().to_string_lossy());

        // Parse and detect
        let rows = parse_csv_file(file)?;
        let mut result = redactor.redact_rows(&rows);
        result.input_path = file.clone();

        // Interactive review
        if !result.redactions.is_empty() {
            session.review_file(&mut result)?;
        }

        // Apply redactions if not dry run
        if !args.dry_run && !result.redactions.is_empty() {
            let output_path = args.output.as_ref()
                .map(|o| o.join(file.file_name().unwrap()))
                .unwrap_or_else(|| {
                    let stem = file.file_stem().unwrap().to_string_lossy();
                    let ext = file.extension().map(|e| e.to_string_lossy()).unwrap_or_default();
                    file.with_file_name(format!("{}.anonymized.{}", stem, ext))
                });

            write_csv_file(&rows, &result.redactions, &output_path)?;
        }

        all_results.push(result);
    }

    // Write report if requested
    if let Some(report_path) = &args.report {
        write_report(&all_results, report_path)?;
        eprintln!("Report written to: {}", report_path.display());
    }

    Ok(())
}

fn process_file(
    file: &PathBuf,
    args: &Args,
    redactor: &Arc<Redactor>,
) -> Result<FileRedactionResult> {
    // Parse CSV
    let rows = parse_csv_file(file)
        .with_context(|| format!("Failed to parse: {}", file.display()))?;

    // Detect and redact
    let mut result = redactor.redact_rows(&rows);
    result.input_path = file.clone();

    // Write output if not dry run
    if !args.dry_run && !result.redactions.is_empty() {
        let output_path = args.output.as_ref()
            .map(|o| o.join(file.file_name().unwrap()))
            .unwrap_or_else(|| {
                let stem = file.file_stem().unwrap().to_string_lossy();
                let ext = file.extension().map(|e| e.to_string_lossy()).unwrap_or_default();
                file.with_file_name(format!("{}.anonymized.{}", stem, ext))
            });

        write_csv_file(&rows, &result.redactions, &output_path)?;
    }

    Ok(result)
}

