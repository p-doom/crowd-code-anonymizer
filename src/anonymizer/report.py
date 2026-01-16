"""Report generation for anonymization results."""

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .redactor import FileRedactionResult, Redaction


def redaction_to_dict(redaction: Redaction) -> dict[str, Any]:
    """Convert a Redaction to a JSON-serializable dict."""
    return {
        "start": redaction.start,
        "end": redaction.end,
        "original_length": len(redaction.original_text),
        "redaction_label": redaction.redaction_label,
        "source": redaction.source,
        "replacement": redaction.replacement,
        # Don't include original_text to avoid leaking secrets in report
    }


def file_result_to_dict(result: FileRedactionResult) -> dict[str, Any]:
    """Convert a FileRedactionResult to a JSON-serializable dict."""
    return {
        "input_path": str(result.input_path),
        "output_path": str(result.output_path) if result.output_path else None,
        "total_rows": result.total_rows,
        "modified_rows": result.modified_rows,
        "total_redactions": result.total_redactions,
        "redactions_by_source": result.get_redactions_by_source(),
        "redactions_by_type": result.get_redactions_by_type(),
        "row_details": [
            {
                "row_index": row_result.row_index,
                "redaction_count": len(row_result.redactions),
                "redactions": [redaction_to_dict(r) for r in row_result.redactions],
            }
            for row_result in result.row_results
            if row_result.was_modified
        ],
    }


def generate_summary(results: list[FileRedactionResult]) -> dict[str, Any]:
    """Generate a summary of all redaction results."""
    total_files = len(results)
    total_rows = sum(r.total_rows for r in results)
    total_modified_rows = sum(r.modified_rows for r in results)
    total_redactions = sum(r.total_redactions for r in results)
    
    # Aggregate by source
    by_source: dict[str, int] = {"secrets": 0, "pii": 0, "custom": 0}
    for result in results:
        for source, count in result.get_redactions_by_source().items():
            by_source[source] = by_source.get(source, 0) + count
    
    # Aggregate by type
    by_type: dict[str, int] = {}
    for result in results:
        for redaction_type, count in result.get_redactions_by_type().items():
            by_type[redaction_type] = by_type.get(redaction_type, 0) + count
    
    return {
        "total_files": total_files,
        "total_rows": total_rows,
        "modified_rows": total_modified_rows,
        "total_redactions": total_redactions,
        "redactions_by_source": by_source,
        "redactions_by_type": dict(sorted(by_type.items(), key=lambda x: -x[1])),
    }


def generate_report(
    results: list[FileRedactionResult],
    include_details: bool = True,
) -> dict[str, Any]:
    """Generate a complete JSON report of anonymization results.
    
    Args:
        results: List of FileRedactionResult objects
        include_details: If True, include per-row details
        
    Returns:
        JSON-serializable dict with the report
    """
    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": generate_summary(results),
    }
    
    if include_details:
        report["files"] = [file_result_to_dict(r) for r in results]
    else:
        report["files"] = [
            {
                "input_path": str(r.input_path),
                "output_path": str(r.output_path) if r.output_path else None,
                "total_rows": r.total_rows,
                "modified_rows": r.modified_rows,
                "total_redactions": r.total_redactions,
            }
            for r in results
        ]
    
    return report


def write_report(
    results: list[FileRedactionResult],
    output_path: Path,
    include_details: bool = True,
) -> None:
    """Write a JSON report to a file.
    
    Args:
        results: List of FileRedactionResult objects
        output_path: Path to write the report
        include_details: If True, include per-row details
    """
    report = generate_report(results, include_details=include_details)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)


def print_summary(results: list[FileRedactionResult]) -> None:
    """Print a human-readable summary to stdout."""
    summary = generate_summary(results)
    
    print("\n" + "=" * 60)
    print("ANONYMIZATION SUMMARY")
    print("=" * 60)
    print(f"Files processed:    {summary['total_files']}")
    print(f"Total rows:         {summary['total_rows']}")
    print(f"Modified rows:      {summary['modified_rows']}")
    print(f"Total redactions:   {summary['total_redactions']}")
    
    print("\nRedactions by detection layer:")
    for source, count in summary['redactions_by_source'].items():
        if count > 0:
            print(f"  {source:15} {count:5}")
    
    if summary['redactions_by_type']:
        print("\nTop redaction types:")
        for redaction_type, count in list(summary['redactions_by_type'].items())[:10]:
            print(f"  {redaction_type:20} {count:5}")
    
    print("=" * 60 + "\n")

