"""CSV parser for crowd-code recording format."""

import csv
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Increase CSV field size limit to handle large file contents
# Default is 128KB, we set it to 50MB to handle large files
csv.field_size_limit(50 * 1024 * 1024)


@dataclass
class CSVRow:
    """Represents a single row from a crowd-code CSV recording."""
    
    sequence: int
    time: int
    file: str
    range_offset: int
    range_length: int
    text: str
    language: str
    row_type: str
    raw_row: list[str]
    row_index: int
    
    @property
    def is_terminal(self) -> bool:
        """Check if this row is from terminal activity."""
        return self.row_type in ("terminal_command", "terminal_output", "terminal_focus")
    
    @property
    def is_high_risk(self) -> bool:
        """Check if this row type has high risk of containing secrets."""
        return self.row_type in ("terminal_command", "terminal_output")
    
    @property
    def is_content(self) -> bool:
        """Check if this row contains file content."""
        return self.row_type in ("content", "tab")


def unescape_csv_text(text: str) -> str:
    """Unescape text from crowd-code CSV format.
    
    Reverses the escaping done by crowd-code's escapeString function:
    - "" -> "
    - \\r\\n -> \r\n
    - \\n -> \n
    - \\r -> \r
    - \\t -> \t
    """
    return (
        text
        .replace('""', '"')
        .replace('\\r\\n', '\r\n')
        .replace('\\n', '\n')
        .replace('\\r', '\r')
        .replace('\\t', '\t')
    )


def escape_csv_text(text: str) -> str:
    """Escape text back to crowd-code CSV format.
    
    Applies the same escaping as crowd-code's escapeString function:
    - " -> ""
    - \r\n -> \\r\\n
    - \n -> \\n
    - \r -> \\r
    - \t -> \\t
    """
    return (
        text
        .replace('"', '""')
        .replace('\r\n', '\\r\\n')
        .replace('\n', '\\n')
        .replace('\r', '\\r')
        .replace('\t', '\\t')
    )


def parse_csv_line(line: str) -> list[str]:
    """Parse a single CSV line handling quoted fields with commas.
    
    Uses regex to split on commas that are not inside quoted strings.
    """
    # Match fields: either quoted (with possible escaped quotes) or unquoted
    pattern = r',(?=(?:[^"]*"[^"]*")*[^"]*$)'
    return re.split(pattern, line)


def parse_csv_file(file_path: Path) -> Iterator[CSVRow]:
    """Parse a crowd-code CSV file and yield CSVRow objects.
    
    Args:
        file_path: Path to the CSV file
        
    Yields:
        CSVRow objects for each data row (skips header)
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        
        # Skip header row
        try:
            header = next(reader)
        except StopIteration:
            return
        
        for row_index, row in enumerate(reader, start=1):
            if len(row) < 8:
                # Skip malformed rows
                continue
            
            try:
                sequence = int(row[0])
                time = int(row[1])
                file_name = row[2]
                range_offset = int(row[3])
                range_length = int(row[4])
                text = unescape_csv_text(row[5])
                language = row[6] if len(row) > 6 else ""
                row_type = row[7] if len(row) > 7 else "content"
                
                yield CSVRow(
                    sequence=sequence,
                    time=time,
                    file=file_name,
                    range_offset=range_offset,
                    range_length=range_length,
                    text=text,
                    language=language,
                    row_type=row_type,
                    raw_row=row,
                    row_index=row_index,
                )
            except (ValueError, IndexError):
                # Skip rows that can't be parsed
                continue


def write_csv_file(
    file_path: Path,
    rows: list[CSVRow],
    modified_texts: dict[int, str],
) -> None:
    """Write a CSV file with modified text content.
    
    Args:
        file_path: Path to write the output CSV
        rows: Original CSVRow objects
        modified_texts: Dict mapping row_index to new text content
    """
    with open(file_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        
        # Write header
        writer.writerow([
            "Sequence", "Time", "File", "RangeOffset", 
            "RangeLength", "Text", "Language", "Type"
        ])
        
        for row in rows:
            text = modified_texts.get(row.row_index, row.text)
            escaped_text = escape_csv_text(text)
            
            writer.writerow([
                row.sequence,
                row.time,
                row.file,
                row.range_offset,
                row.range_length,
                escaped_text,
                row.language,
                row.row_type,
            ])


def find_csv_files(path: Path, recursive: bool = False) -> list[Path]:
    """Find all CSV files in a path.
    
    Args:
        path: File or directory path
        recursive: If True and path is a directory, search recursively
        
    Returns:
        List of CSV file paths
    """
    if path.is_file():
        if path.suffix.lower() == '.csv':
            return [path]
        return []
    
    if path.is_dir():
        pattern = '**/*.csv' if recursive else '*.csv'
        return list(path.glob(pattern))
    
    return []

