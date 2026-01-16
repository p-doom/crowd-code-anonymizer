"""Redactor that combines findings from all detectors and applies redactions."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol
import time

from .csv_parser import CSVRow, find_csv_files, parse_csv_file, write_csv_file


class ProgressCallback(Protocol):
    """Protocol for progress reporting callbacks."""
    
    def __call__(
        self,
        current: int,
        total: int,
        message: str,
        **kwargs,
    ) -> None:
        """Report progress.
        
        Args:
            current: Current item number
            total: Total number of items
            message: Status message
            **kwargs: Additional info (e.g., file_path, rows_per_sec, etc.)
        """
        ...
from .detectors import SecretsDetector, PIIDetector, CustomDetector
from .detectors.secrets import SecretFinding
from .detectors.pii import PIIFinding
from .detectors.custom import CustomFinding


@dataclass
class Redaction:
    """Represents a single redaction to be applied."""
    
    start: int
    end: int
    original_text: str
    redaction_label: str
    source: str  # "secrets", "pii", or "custom"
    
    @property
    def replacement(self) -> str:
        """Get the replacement text for this redaction."""
        return f"[REDACTED:{self.redaction_label}]"


@dataclass
class RowRedactionResult:
    """Result of redacting a single row."""
    
    row_index: int
    original_text: str
    redacted_text: str
    redactions: list[Redaction] = field(default_factory=list)
    
    @property
    def was_modified(self) -> bool:
        """Check if any redactions were applied."""
        return len(self.redactions) > 0


@dataclass
class FileRedactionResult:
    """Result of redacting a single CSV file."""
    
    input_path: Path
    output_path: Path | None
    total_rows: int
    modified_rows: int
    row_results: list[RowRedactionResult] = field(default_factory=list)
    
    @property
    def total_redactions(self) -> int:
        """Total number of redactions applied."""
        return sum(len(r.redactions) for r in self.row_results)
    
    def get_redactions_by_source(self) -> dict[str, int]:
        """Get count of redactions grouped by source detector."""
        counts: dict[str, int] = {"secrets": 0, "pii": 0, "custom": 0}
        for row_result in self.row_results:
            for redaction in row_result.redactions:
                counts[redaction.source] = counts.get(redaction.source, 0) + 1
        return counts
    
    def get_redactions_by_type(self) -> dict[str, int]:
        """Get count of redactions grouped by redaction label."""
        counts: dict[str, int] = {}
        for row_result in self.row_results:
            for redaction in row_result.redactions:
                counts[redaction.redaction_label] = counts.get(redaction.redaction_label, 0) + 1
        return counts


class Redactor:
    """Combines all detectors and applies redactions to CSV files."""
    
    def __init__(self, strict: bool = False):
        """Initialize the redactor with all detection layers.
        
        Args:
            strict: If True, use more aggressive detection settings
        """
        self.strict = strict
        self.secrets_detector = SecretsDetector(strict=strict)
        self.pii_detector = PIIDetector(strict=strict)
        self.custom_detector = CustomDetector(strict=strict)
    
    def _merge_findings(
        self,
        text: str,
        secret_findings: list[SecretFinding],
        pii_findings: list[PIIFinding],
        custom_findings: list[CustomFinding],
    ) -> list[Redaction]:
        """Merge findings from all detectors into a unified list of redactions.
        
        Handles overlapping findings by preferring the most specific match.
        
        Args:
            text: Original text
            secret_findings: Findings from detect-secrets
            pii_findings: Findings from Presidio
            custom_findings: Findings from custom patterns
            
        Returns:
            List of Redaction objects sorted by position
        """
        redactions: list[Redaction] = []
        
        # Convert secret findings
        for finding in secret_findings:
            if finding.start >= 0 and finding.end > finding.start:
                redactions.append(Redaction(
                    start=finding.start,
                    end=finding.end,
                    original_text=finding.secret_value,
                    redaction_label=finding.redaction_label,
                    source="secrets",
                ))
        
        # Convert PII findings
        for finding in pii_findings:
            redactions.append(Redaction(
                start=finding.start,
                end=finding.end,
                original_text=finding.text,
                redaction_label=finding.redaction_label,
                source="pii",
            ))
        
        # Convert custom findings
        for finding in custom_findings:
            redactions.append(Redaction(
                start=finding.start,
                end=finding.end,
                original_text=finding.matched_text,
                redaction_label=finding.redaction_label,
                source="custom",
            ))
        
        # Sort by start position, then by length (longer matches first for overlaps)
        redactions.sort(key=lambda r: (r.start, -(r.end - r.start)))
        
        # Remove overlapping redactions (keep the first/longest one)
        filtered: list[Redaction] = []
        last_end = -1
        
        for redaction in redactions:
            if redaction.start >= last_end:
                filtered.append(redaction)
                last_end = redaction.end
        
        return filtered
    
    def _apply_redactions(self, text: str, redactions: list[Redaction]) -> str:
        """Apply redactions to text.
        
        Args:
            text: Original text
            redactions: List of redactions (must be non-overlapping and sorted)
            
        Returns:
            Redacted text
        """
        if not redactions:
            return text
        
        # Apply redactions from end to start to preserve positions
        result = text
        for redaction in reversed(redactions):
            result = result[:redaction.start] + redaction.replacement + result[redaction.end:]
        
        return result

    def apply_redactions(self, text: str, redactions: list[Redaction]) -> str:
        """Apply redactions to text (public wrapper)."""
        return self._apply_redactions(text, redactions)
    
    def redact_text(self, text: str) -> RowRedactionResult:
        """Redact sensitive data from a single text string.
        
        Args:
            text: Text to redact
            
        Returns:
            RowRedactionResult with the redacted text
        """
        # Run all detectors
        secret_findings = self.secrets_detector.detect_multiline(text)
        pii_findings = self.pii_detector.detect_multiline(text)
        custom_findings = self.custom_detector.detect_multiline(text)
        
        # Merge and filter findings
        redactions = self._merge_findings(
            text, secret_findings, pii_findings, custom_findings
        )
        
        # Apply redactions
        redacted_text = self._apply_redactions(text, redactions)
        
        return RowRedactionResult(
            row_index=-1,
            original_text=text,
            redacted_text=redacted_text,
            redactions=redactions,
        )
    
    def redact_csv_row(self, row: CSVRow) -> RowRedactionResult:
        """Redact sensitive data from a CSV row.
        
        Args:
            row: CSVRow to redact
            
        Returns:
            RowRedactionResult with the redacted text
        """
        if row.is_terminal:
            secret_findings = self.secrets_detector.detect_multiline(row.text)
        else:
            secret_findings = []
        pii_findings = self.pii_detector.detect_multiline(row.text)
        custom_findings = self.custom_detector.detect_multiline(row.text)
        
        redactions = self._merge_findings(
            row.text,
            secret_findings,
            pii_findings,
            custom_findings,
        )
        
        redacted_text = self._apply_redactions(row.text, redactions)
        
        return RowRedactionResult(
            row_index=row.row_index,
            original_text=row.text,
            redacted_text=redacted_text,
            redactions=redactions,
        )
    
    def redact_csv_file(
        self,
        input_path: Path,
        output_path: Path | None = None,
        dry_run: bool = False,
        batch_size: int = 64,
        progress_callback: ProgressCallback | None = None,
    ) -> FileRedactionResult:
        """Redact a CSV file using batch processing for GPU efficiency.
        
        Args:
            input_path: Path to input CSV
            output_path: Path for output (if None, generates based on input)
            dry_run: If True, don't write output file
            batch_size: Number of rows to process at once (higher = better GPU utilization)
            progress_callback: Optional callback for progress reporting
            
        Returns:
            FileRedactionResult with details of all redactions
        """
        if output_path is None:
            output_path = input_path.with_suffix('.anonymized.csv')
        
        rows: list[CSVRow] = list(parse_csv_file(input_path))
        row_results: list[RowRedactionResult] = []
        modified_texts: dict[int, str] = {}
        total_rows = len(rows)
        total_redactions = 0
        
        start_time = time.time()
        last_progress_time = start_time
        
        # Process rows in batches for GPU efficiency
        for i in range(0, len(rows), batch_size):
            batch_rows = rows[i:i + batch_size]
            batch_texts = [row.text for row in batch_rows]
            batch_num = i // batch_size + 1
            total_batches = (total_rows + batch_size - 1) // batch_size
            
            # Batch detect PII (main bottleneck - benefits most from batching)
            pii_findings_batch = self.pii_detector.detect_batch(batch_texts)
            
            # Process each row in the batch
            for j, row in enumerate(batch_rows):
                # Get PII findings for this row from batch results
                pii_findings = pii_findings_batch[j] if j < len(pii_findings_batch) else []
                
                # Run other detectors (these are fast, don't need batching)
                secret_findings = self.secrets_detector.detect_multiline(row.text)
                custom_findings = self.custom_detector.detect_multiline(row.text)
                
                # Merge and apply redactions
                redactions = self._merge_findings(
                    row.text, secret_findings, pii_findings, custom_findings
                )
                redacted_text = self._apply_redactions(row.text, redactions)
                
                result = RowRedactionResult(
                    row_index=row.row_index,
                    original_text=row.text,
                    redacted_text=redacted_text,
                    redactions=redactions,
                )
                row_results.append(result)
                total_redactions += len(redactions)
                
                if result.was_modified:
                    modified_texts[row.row_index] = result.redacted_text
            
            # Report progress after each batch
            if progress_callback:
                current_row = min(i + batch_size, total_rows)
                elapsed = time.time() - start_time
                rows_per_sec = current_row / elapsed if elapsed > 0 else 0
                eta_seconds = (total_rows - current_row) / rows_per_sec if rows_per_sec > 0 else 0
                
                progress_callback(
                    current=current_row,
                    total=total_rows,
                    message=f"Batch {batch_num}/{total_batches}",
                    file_path=str(input_path),
                    rows_per_sec=rows_per_sec,
                    eta_seconds=eta_seconds,
                    redactions_found=total_redactions,
                )
        
        # Write output file unless dry run
        actual_output: Path | None = None
        if not dry_run and modified_texts:
            write_csv_file(output_path, rows, modified_texts)
            actual_output = output_path
        elif not dry_run and not modified_texts:
            # No modifications, copy original
            import shutil
            shutil.copy(input_path, output_path)
            actual_output = output_path
        
        return FileRedactionResult(
            input_path=input_path,
            output_path=actual_output,
            total_rows=len(rows),
            modified_rows=len([r for r in row_results if r.was_modified]),
            row_results=row_results,
        )
    
    def redact_directory(
        self,
        directory: Path,
        output_directory: Path | None = None,
        recursive: bool = False,
        dry_run: bool = False,
        batch_size: int = 64,
        progress_callback: ProgressCallback | None = None,
        file_callback: Callable[[int, int, Path], None] | None = None,
    ) -> list[FileRedactionResult]:
        """Redact all CSV files in a directory.
        
        Args:
            directory: Directory containing CSV files
            output_directory: Directory for output files (if None, uses same directory)
            recursive: If True, process subdirectories
            dry_run: If True, don't write output files
            batch_size: Batch size for GPU processing
            progress_callback: Callback for row-level progress
            file_callback: Callback when starting a new file (file_num, total_files, path)
            
        Returns:
            List of FileRedactionResult for each file
        """
        csv_files = find_csv_files(directory, recursive=recursive)
        results: list[FileRedactionResult] = []
        total_files = len(csv_files)
        
        for file_num, csv_file in enumerate(csv_files, 1):
            if file_callback:
                file_callback(file_num, total_files, csv_file)
            
            if output_directory:
                # Preserve relative structure in output directory
                relative = csv_file.relative_to(directory)
                output_path = output_directory / relative.with_suffix('.anonymized.csv')
                output_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                output_path = None
            
            result = self.redact_csv_file(
                csv_file, 
                output_path, 
                dry_run=dry_run,
                batch_size=batch_size,
                progress_callback=progress_callback,
            )
            results.append(result)
        
        return results

    def redact_csv_file_review(
        self,
        input_path: Path,
        review_fn: Callable[[Path, CSVRow, Redaction], bool | str],
        output_path: Path | None = None,
        dry_run: bool = False,
        checkpoint: bool = False,
    ) -> FileRedactionResult:
        """Redact a CSV file with per-finding review.
        
        Args:
            input_path: Path to input CSV
            review_fn: Callback to accept/reject each redaction.
                       Return True to accept, False to reject, "redo" to go back.
            output_path: Path for output (if None, generates based on input)
            dry_run: If True, don't write output file
            checkpoint: If True, write output after each decision
        """
        if output_path is None:
            output_path = input_path.with_suffix('.anonymized.csv')
        
        rows: list[CSVRow] = list(parse_csv_file(input_path))
        
        # Collect all redactions across all rows for unified navigation
        all_items: list[tuple[CSVRow, RowRedactionResult, Redaction]] = []
        row_results_map: dict[int, RowRedactionResult] = {}
        
        for row in rows:
            row_result = self.redact_csv_row(row)
            row_results_map[row.row_index] = row_result
            for redaction in row_result.redactions:
                all_items.append((row, row_result, redaction))
        
        # Track decisions for each item
        decisions: list[bool | None] = [None] * len(all_items)
        modified_texts: dict[int, str] = {}
        
        # Process all redactions with ability to go back across rows
        index = 0
        while index < len(all_items):
            row, row_result, redaction = all_items[index]
            decision = review_fn(input_path, row, redaction)
            
            if decision == "redo":
                if index > 0:
                    decisions[index - 1] = None
                    index -= 1
                continue
            
            decisions[index] = bool(decision)
            index += 1
            
            if checkpoint and not dry_run:
                self._update_modified_texts(
                    all_items, decisions, row_results_map, modified_texts
                )
                write_csv_file(output_path, rows, modified_texts)
        
        # Build final row results with accepted redactions only
        self._update_modified_texts(all_items, decisions, row_results_map, modified_texts)
        
        final_row_results: list[RowRedactionResult] = []
        for row in rows:
            original_result = row_results_map[row.row_index]
            if not original_result.redactions:
                final_row_results.append(original_result)
                continue
            
            # Find accepted redactions for this row
            accepted = [
                redaction for i, (r, _, redaction) in enumerate(all_items)
                if r.row_index == row.row_index and decisions[i]
            ]
            
            if len(accepted) != len(original_result.redactions):
                redacted_text = self._apply_redactions(row.text, accepted)
                final_row_results.append(RowRedactionResult(
                    row_index=row.row_index,
                    original_text=row.text,
                    redacted_text=redacted_text,
                    redactions=accepted,
                ))
            else:
                final_row_results.append(original_result)
        
        actual_output: Path | None = None
        if not dry_run and modified_texts:
            write_csv_file(output_path, rows, modified_texts)
            actual_output = output_path
        elif not dry_run and not modified_texts:
            import shutil
            shutil.copy(input_path, output_path)
            actual_output = output_path
        
        return FileRedactionResult(
            input_path=input_path,
            output_path=actual_output,
            total_rows=len(rows),
            modified_rows=len([r for r in final_row_results if r.was_modified]),
            row_results=final_row_results,
        )
    
    def _update_modified_texts(
        self,
        all_items: list[tuple[CSVRow, RowRedactionResult, Redaction]],
        decisions: list[bool | None],
        row_results_map: dict[int, RowRedactionResult],
        modified_texts: dict[int, str],
    ) -> None:
        """Update modified_texts dict based on current decisions."""
        # Group accepted redactions by row
        accepted_by_row: dict[int, list[Redaction]] = {}
        for i, (row, _, redaction) in enumerate(all_items):
            if decisions[i]:
                if row.row_index not in accepted_by_row:
                    accepted_by_row[row.row_index] = []
                accepted_by_row[row.row_index].append(redaction)
        
        # Update modified_texts
        modified_texts.clear()
        for row_index, redactions in accepted_by_row.items():
            original_result = row_results_map[row_index]
            modified_texts[row_index] = self._apply_redactions(
                original_result.original_text, redactions
            )


    def redact_directory_review(
        self,
        directory: Path,
        review_fn: Callable[[Path, CSVRow, Redaction], bool | str],
        output_directory: Path | None = None,
        recursive: bool = False,
        dry_run: bool = False,
        checkpoint: bool = False,
    ) -> list[FileRedactionResult]:
        """Redact all CSV files in a directory with per-finding review."""
        csv_files = find_csv_files(directory, recursive=recursive)
        results: list[FileRedactionResult] = []
        
        for csv_file in csv_files:
            if output_directory:
                relative = csv_file.relative_to(directory)
                output_path = output_directory / relative.with_suffix('.anonymized.csv')
                output_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                output_path = None
            
            result = self.redact_csv_file_review(
                csv_file,
                review_fn=review_fn,
                output_path=output_path,
                dry_run=dry_run,
                checkpoint=checkpoint,
            )
            results.append(result)
        
        return results
