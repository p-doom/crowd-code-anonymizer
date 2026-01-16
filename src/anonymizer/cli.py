"""CLI entry point for the anonymizer."""

import sys
import json
from difflib import SequenceMatcher
from pathlib import Path

import click

from .redactor import Redactor, Redaction
from .csv_parser import CSVRow
from .report import print_summary, write_report


def _similarity_ratio(s1: str, s2: str) -> float:
    """Calculate similarity ratio between two strings.
    
    Uses SequenceMatcher which finds the longest contiguous matching
    subsequence, then recursively matches on the parts before/after.
    This is faster than Levenshtein for longer strings and works well
    for structured text like file paths.
    
    Returns a value between 0.0 (completely different) and 1.0 (identical).
    """
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0
    
    # Quick length check - very different lengths unlikely to match
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) / max(len1, len2) > 0.5:
        return 0.0
    
    # SequenceMatcher with autojunk=False for accurate comparison
    return SequenceMatcher(None, s1, s2, autojunk=False).ratio()


def _find_similar_in_cache(
    text: str,
    cache: dict[str, bool],
    threshold: float,
) -> tuple[str, bool] | None:
    """Find a similar text in the cache using sequence matching.
    
    Args:
        text: The text to look up
        cache: Dictionary mapping texts to decisions
        threshold: Minimum similarity ratio (0.0-1.0) to consider a match
        
    Returns:
        Tuple of (matched_text, decision) if found, None otherwise
    """
    if not cache or threshold >= 1.0:
        return None
    
    best_match: str | None = None
    best_ratio = threshold  # Only consider matches above threshold
    
    for cached_text in cache:
        # Quick reject: use quick_ratio first (upper bound on ratio)
        matcher = SequenceMatcher(None, text, cached_text, autojunk=False)
        if matcher.quick_ratio() <= best_ratio:
            continue
        # Get actual ratio only if quick_ratio passes
        ratio = matcher.ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = cached_text
    
    if best_match is not None:
        return (best_match, cache[best_match])
    return None


def _line_col(text: str, offset: int) -> tuple[int, int]:
    """Convert an offset into 1-based line and column."""
    line = text.count('\n', 0, offset) + 1
    last_newline = text.rfind('\n', 0, offset)
    column = offset - last_newline
    return line, column


def _make_context_snippet_parts(
    text: str,
    start: int,
    end: int,
    context: int = 40,
) -> tuple[str, str, str]:
    """Create a compact, single-line snippet for review."""
    snippet_start = max(0, start - context)
    snippet_end = min(len(text), end + context)
    snippet = text[snippet_start:snippet_end].replace('\n', '\\n')
    marker_start = start - snippet_start
    marker_end = end - snippet_start
    return (
        snippet[:marker_start],
        snippet[marker_start:marker_end],
        snippet[marker_end:],
    )


def _prompt_review(
    input_path: Path,
    row: CSVRow,
    redaction: Redaction,
    last_choice: dict[str, bool | None],
) -> bool | str:
    """Prompt the user to accept or reject a redaction."""
    line, column = _line_col(row.text, redaction.start)
    click.echo("")
    click.echo(f"File: {input_path}")
    click.echo(f"Row: {row.row_index} Type: {row.row_type} Line: {line} Col: {column}")
    click.echo(f"Source: {redaction.source} Label: {redaction.redaction_label}")
    before, focus, after = _make_context_snippet_parts(
        row.text,
        redaction.start,
        redaction.end,
    )
    click.echo("Context: ", nl=False)
    click.echo(before, nl=False)
    click.secho(focus, nl=False, fg="red")
    click.echo(after)
    
    while True:
        click.echo("Accept redaction? (y/n, arrows: left=no right=yes up=redo) ", nl=False)
        choice = click.getchar()
        
        if isinstance(choice, str) and choice.startswith("\x1b"):
            if choice == "\x1b":
                next_char = click.getchar()
                if next_char == "[":
                    arrow = click.getchar()
                    choice = f"\x1b[{arrow}"
            if choice in ("\x1b[C", "\x1b[D", "\x1b[A"):
                if choice == "\x1b[C":
                    click.echo("[right]")
                    last_choice["value"] = True
                    return True
                if choice == "\x1b[D":
                    click.echo("[left]")
                    last_choice["value"] = False
                    return False
                if choice == "\x1b[A":
                    click.echo("[up]")
                    return "redo"
        
        click.echo(choice)
        if isinstance(choice, str):
            choice = choice.strip().lower()
        if choice in ("y", "yes"):
            last_choice["value"] = True
            return True
        if choice in ("n", "no"):
            last_choice["value"] = False
            return False
        click.echo("Please press 'y' or 'n' (or use arrow keys).")


def _review_key(input_path: Path, row: CSVRow, redaction: Redaction) -> str:
    return json.dumps({
        "path": str(input_path),
        "row_index": row.row_index,
        "start": redaction.start,
        "end": redaction.end,
        "label": redaction.redaction_label,
        "source": redaction.source,
        "text": redaction.original_text,
    }, sort_keys=True)


def _load_review_state(state_path: Path) -> tuple[dict[str, bool], dict[str, bool]]:
    decisions: dict[str, bool] = {}
    text_cache: dict[str, bool] = {}
    if not state_path.exists():
        return decisions, text_cache
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                record_type = record.get("type")
                if record_type == "text_cache":
                    text = record.get("text")
                    decision = record.get("decision")
                    if isinstance(text, str) and isinstance(decision, bool):
                        text_cache[text] = decision
                    continue
                key = json.dumps({
                    "path": record.get("path"),
                    "row_index": record.get("row_index"),
                    "start": record.get("start"),
                    "end": record.get("end"),
                    "label": record.get("label"),
                    "source": record.get("source"),
                    "text": record.get("text"),
                }, sort_keys=True)
                decisions[key] = bool(record.get("decision"))
    except Exception:
        return decisions, text_cache
    return decisions, text_cache


def _append_review_state(state_path: Path, key: str, decision: bool) -> None:
    record = json.loads(key)
    record["type"] = "decision"
    record["decision"] = decision
    with open(state_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def _append_text_cache(state_path: Path, text: str, decision: bool) -> None:
    record = {
        "type": "text_cache",
        "text": text,
        "decision": decision,
    }
    with open(state_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


@click.command()
@click.argument(
    'input_path',
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    '-o', '--output',
    type=click.Path(path_type=Path),
    help='Output file or directory path. If not specified, creates .anonymized.csv files.',
)
@click.option(
    '-r', '--recursive',
    is_flag=True,
    default=False,
    help='Process directories recursively.',
)
@click.option(
    '--dry-run',
    is_flag=True,
    default=False,
    help='Show what would be redacted without writing files.',
)
@click.option(
    '--strict',
    is_flag=True,
    default=False,
    help='Use more aggressive detection (lower thresholds, more patterns).',
)
@click.option(
    '--report',
    'report_path',
    type=click.Path(path_type=Path),
    help='Write a JSON report to this path.',
)
@click.option(
    '--review-state',
    'review_state_path',
    type=click.Path(path_type=Path),
    help='Path to store/reuse review decisions (JSONL).',
)
@click.option(
    '--review',
    is_flag=True,
    default=False,
    help='Review each redaction and accept/reject interactively.',
)
@click.option(
    '--similarity-threshold',
    'similarity_threshold',
    type=click.FloatRange(0.0, 1.0),
    default=1.0,
    help='Similarity threshold (0.0-1.0) for fuzzy matching cached decisions. '
         'Default 1.0 requires exact match. Use ~0.85 for fuzzy matching.',
)
@click.option(
    '--quiet', '-q',
    is_flag=True,
    default=False,
    help='Suppress output except errors.',
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    default=False,
    help='Show detailed output for each file.',
)
def main(
    input_path: Path,
    output: Path | None,
    recursive: bool,
    dry_run: bool,
    strict: bool,
    report_path: Path | None,
    review_state_path: Path | None,
    review: bool,
    similarity_threshold: float,
    quiet: bool,
    verbose: bool,
) -> None:
    """Anonymize sensitive data in crowd-code CSV files.
    
    INPUT_PATH can be a single CSV file or a directory containing CSV files.
    
    Examples:
    
      \b
      # Anonymize a single file
      anonymize source.csv
      
      \b
      # Anonymize with specific output path
      anonymize source.csv -o anonymized.csv
      
      \b
      # Process a directory recursively
      anonymize ./recordings/ --recursive
      
      \b
      # Dry run to see what would be redacted
      anonymize source.csv --dry-run
      
      \b
      # Generate a detailed report
      anonymize source.csv --report report.json
      
      \b
      # Use strict mode for more aggressive detection
      anonymize source.csv --strict
    """
    # Validate options
    if quiet and verbose:
        click.echo("Error: Cannot use --quiet and --verbose together.", err=True)
        sys.exit(1)
    if quiet and review:
        click.echo("Error: Cannot use --quiet and --review together.", err=True)
        sys.exit(1)
    
    # Initialize redactor
    if not quiet:
        click.echo(f"Initializing anonymizer (strict={strict})...")
    
    try:
        redactor = Redactor(strict=strict)
    except Exception as e:
        click.echo(f"Error initializing redactor: {e}", err=True)
        sys.exit(1)
    
    # Process input
    results = []
    
    if input_path.is_file():
        # Single file
        if not quiet:
            click.echo(f"Processing: {input_path}")
        
        try:
            if review:
                last_choice: dict[str, bool | None] = {"value": None}
                if review_state_path is None:
                    review_state_path = input_path.with_suffix(".review.jsonl")
                decisions, text_cache = _load_review_state(review_state_path)
                last_reviewed_key: dict[str, str | None] = {"value": None}
                last_reviewed_text: dict[str, str | None] = {"value": None}
                pending_redo_key: dict[str, str | None] = {"value": None}
                
                def review_fn(path: Path, row: CSVRow, redaction: Redaction) -> bool | str:
                    key = _review_key(path, row, redaction)
                    
                    # Check if we just tried to redo but got the same redaction back
                    # (meaning we're at the first redaction in this row and can't go back)
                    if pending_redo_key["value"] == key:
                        click.echo("(Cannot go back further - at the first redaction)")
                        pending_redo_key["value"] = None
                    
                    # Check caches and track as last reviewed if found
                    # First try exact match
                    if redaction.original_text in text_cache:
                        last_reviewed_key["value"] = key
                        last_reviewed_text["value"] = redaction.original_text
                        return text_cache[redaction.original_text]
                    # Try fuzzy match if threshold is set
                    if similarity_threshold < 1.0:
                        similar = _find_similar_in_cache(
                            redaction.original_text, text_cache, similarity_threshold
                        )
                        if similar is not None:
                            matched_text, cached_decision = similar
                            last_reviewed_key["value"] = key
                            last_reviewed_text["value"] = matched_text
                            # Also cache this exact text for future exact matches
                            text_cache[redaction.original_text] = cached_decision
                            return cached_decision
                    if key in decisions:
                        last_reviewed_key["value"] = key
                        last_reviewed_text["value"] = redaction.original_text
                        return decisions[key]
                    # Not in cache, prompt user
                    decision = _prompt_review(path, row, redaction, last_choice)
                    if decision == "redo":
                        # Track that we're attempting a redo from this redaction
                        pending_redo_key["value"] = key
                        # Remove the last reviewed redaction from caches so it can be re-prompted
                        if last_reviewed_key["value"] is not None:
                            decisions.pop(last_reviewed_key["value"], None)
                        if last_reviewed_text["value"] is not None:
                            text_cache.pop(last_reviewed_text["value"], None)
                        return "redo"
                    # At this point, decision is bool (not "redo")
                    assert isinstance(decision, bool)
                    pending_redo_key["value"] = None
                    # Store this as the last reviewed redaction
                    last_reviewed_key["value"] = key
                    last_reviewed_text["value"] = redaction.original_text
                    decisions[key] = decision
                    _append_review_state(review_state_path, key, decision)
                    text_cache[redaction.original_text] = decision
                    _append_text_cache(review_state_path, redaction.original_text, decision)
                    return decision
                
                result = redactor.redact_csv_file_review(
                    input_path,
                    review_fn=review_fn,
                    output_path=output,
                    dry_run=dry_run,
                    checkpoint=True,
                )
            else:
                result = redactor.redact_csv_file(
                    input_path,
                    output_path=output,
                    dry_run=dry_run,
                )
            results.append(result)
            
            if verbose:
                click.echo(f"  Rows: {result.total_rows}, Modified: {result.modified_rows}, Redactions: {result.total_redactions}")
                if result.output_path:
                    click.echo(f"  Output: {result.output_path}")
        except Exception as e:
            click.echo(f"Error processing {input_path}: {e}", err=True)
            sys.exit(1)
    
    elif input_path.is_dir():
        # Directory
        if not quiet:
            click.echo(f"Processing directory: {input_path} (recursive={recursive})")
        
        try:
            if review:
                last_choice: dict[str, bool | None] = {"value": None}
                if review_state_path is None:
                    review_state_path = input_path / ".review.jsonl"
                decisions, text_cache = _load_review_state(review_state_path)
                last_reviewed_key: dict[str, str | None] = {"value": None}
                last_reviewed_text: dict[str, str | None] = {"value": None}
                pending_redo_key: dict[str, str | None] = {"value": None}
                
                def review_fn(path: Path, row: CSVRow, redaction: Redaction) -> bool | str:
                    key = _review_key(path, row, redaction)
                    
                    # Check if we just tried to redo but got the same redaction back
                    # (meaning we're at the first redaction in this row and can't go back)
                    if pending_redo_key["value"] == key:
                        click.echo("(Cannot go back further - at the first redaction)")
                        pending_redo_key["value"] = None
                    
                    # Check caches and track as last reviewed if found
                    # First try exact match
                    if redaction.original_text in text_cache:
                        last_reviewed_key["value"] = key
                        last_reviewed_text["value"] = redaction.original_text
                        return text_cache[redaction.original_text]
                    # Try fuzzy match if threshold is set
                    if similarity_threshold < 1.0:
                        similar = _find_similar_in_cache(
                            redaction.original_text, text_cache, similarity_threshold
                        )
                        if similar is not None:
                            matched_text, cached_decision = similar
                            last_reviewed_key["value"] = key
                            last_reviewed_text["value"] = matched_text
                            # Also cache this exact text for future exact matches
                            text_cache[redaction.original_text] = cached_decision
                            return cached_decision
                    if key in decisions:
                        last_reviewed_key["value"] = key
                        last_reviewed_text["value"] = redaction.original_text
                        return decisions[key]
                    # Not in cache, prompt user
                    decision = _prompt_review(path, row, redaction, last_choice)
                    if decision == "redo":
                        # Track that we're attempting a redo from this redaction
                        pending_redo_key["value"] = key
                        # Remove the last reviewed redaction from caches so it can be re-prompted
                        if last_reviewed_key["value"] is not None:
                            decisions.pop(last_reviewed_key["value"], None)
                        if last_reviewed_text["value"] is not None:
                            text_cache.pop(last_reviewed_text["value"], None)
                        return "redo"
                    # At this point, decision is bool (not "redo")
                    assert isinstance(decision, bool)
                    pending_redo_key["value"] = None
                    # Store this as the last reviewed redaction
                    last_reviewed_key["value"] = key
                    last_reviewed_text["value"] = redaction.original_text
                    decisions[key] = decision
                    _append_review_state(review_state_path, key, decision)
                    text_cache[redaction.original_text] = decision
                    _append_text_cache(review_state_path, redaction.original_text, decision)
                    return decision
                
                results = redactor.redact_directory_review(
                    input_path,
                    review_fn=review_fn,
                    output_directory=output,
                    recursive=recursive,
                    dry_run=dry_run,
                    checkpoint=True,
                )
            else:
                results = redactor.redact_directory(
                    input_path,
                    output_directory=output,
                    recursive=recursive,
                    dry_run=dry_run,
                )
            
            if not results:
                click.echo("No CSV files found.", err=True)
                sys.exit(0)
            
            for result in results:
                if verbose:
                    click.echo(f"  {result.input_path}: {result.modified_rows}/{result.total_rows} rows modified, {result.total_redactions} redactions")
        except Exception as e:
            click.echo(f"Error processing directory: {e}", err=True)
            sys.exit(1)
    
    else:
        click.echo(f"Error: {input_path} is not a file or directory.", err=True)
        sys.exit(1)
    
    # Generate report if requested
    if report_path:
        try:
            write_report(results, report_path)
            if not quiet:
                click.echo(f"Report written to: {report_path}")
        except Exception as e:
            click.echo(f"Error writing report: {e}", err=True)
    
    # Print summary
    if not quiet:
        print_summary(results)
    
    # Exit with appropriate code
    total_redactions = sum(r.total_redactions for r in results)
    if dry_run and total_redactions > 0:
        click.echo(f"Dry run complete. {total_redactions} redactions would be applied.")
    elif total_redactions > 0:
        click.echo(f"Anonymization complete. {total_redactions} redactions applied.")
    else:
        click.echo("No sensitive data detected.")


if __name__ == '__main__':
    main()
