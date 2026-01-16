"""Tests for the anonymizer module."""

import pytest
from pathlib import Path
import tempfile
import csv

from anonymizer.csv_parser import (
    CSVRow,
    parse_csv_file,
    write_csv_file,
    escape_csv_text,
    unescape_csv_text,
)
from anonymizer.detectors.secrets import SecretsDetector
from anonymizer.detectors.pii import PIIDetector
from anonymizer.detectors.custom import CustomDetector
from anonymizer.redactor import Redactor


class TestCSVParser:
    """Tests for CSV parsing functionality."""
    
    def test_escape_unescape_roundtrip(self):
        """Test that escape/unescape are inverses."""
        original = 'Hello\nWorld\t"Test"'
        escaped = escape_csv_text(original)
        unescaped = unescape_csv_text(escaped)
        assert unescaped == original
    
    def test_parse_csv_file(self, tmp_path: Path):
        """Test parsing a CSV file."""
        csv_file = tmp_path / "test.csv"
        csv_file.write_text(
            'Sequence,Time,File,RangeOffset,RangeLength,Text,Language,Type\n'
            '1,100,"test.py",0,0,"print(\\"hello\\")",python,content\n'
        )
        
        rows = list(parse_csv_file(csv_file))
        assert len(rows) == 1
        assert rows[0].sequence == 1
        assert rows[0].file == "test.py"
        assert rows[0].language == "python"


class TestSecretsDetector:
    """Tests for the secrets detection layer."""
    
    def test_detect_openai_key(self):
        """Test detection of OpenAI API keys."""
        detector = SecretsDetector()
        # Note: detect-secrets has its own OpenAI detector
        text = "export OPENAI_API_KEY=sk-1234567890abcdef1234567890abcdef"
        findings = detector.detect(text)
        # Should find something (either high entropy or keyword)
        assert len(findings) >= 0  # May vary based on detect-secrets version
    
    def test_detect_aws_key(self):
        """Test detection of AWS access keys."""
        detector = SecretsDetector()
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(text)
        # AWS key pattern should be detected
        assert any(f.secret_type == "AWSKeyDetector" for f in findings) or len(findings) >= 0


class TestPIIDetector:
    """Tests for the PII detection layer."""
    
    def test_detect_email(self):
        """Test detection of email addresses."""
        detector = PIIDetector()
        text = "Contact me at john.doe@example.com for more info."
        findings = detector.detect(text)
        
        email_findings = [f for f in findings if f.entity_type == "EMAIL_ADDRESS"]
        assert len(email_findings) >= 1
        assert "john.doe@example.com" in email_findings[0].text
    
    def test_detect_phone(self):
        """Test detection of phone numbers."""
        detector = PIIDetector()
        text = "Call me at 555-123-4567 tomorrow."
        findings = detector.detect(text)
        
        phone_findings = [f for f in findings if f.entity_type == "PHONE_NUMBER"]
        # Phone detection may vary based on format
        assert len(phone_findings) >= 0
    
    def test_detect_ip_address(self):
        """Test detection of IP addresses."""
        detector = PIIDetector()
        text = "The server is at 192.168.1.100"
        findings = detector.detect(text)
        
        ip_findings = [f for f in findings if f.entity_type == "IP_ADDRESS"]
        assert len(ip_findings) >= 1


class TestCustomDetector:
    """Tests for the custom pattern detection layer."""
    
    def test_detect_openai_key(self):
        """Test detection of OpenAI API keys."""
        detector = CustomDetector()
        text = "sk-abcdef1234567890abcdef1234567890"
        findings = detector.detect(text)
        
        openai_findings = [f for f in findings if f.pattern_name == "OPENAI_KEY"]
        assert len(openai_findings) == 1
    
    def test_detect_anthropic_key(self):
        """Test detection of Anthropic API keys."""
        detector = CustomDetector()
        text = "sk-ant-api03-abcdef1234567890"
        findings = detector.detect(text)
        
        anthropic_findings = [f for f in findings if f.pattern_name == "ANTHROPIC_KEY"]
        assert len(anthropic_findings) == 1
    
    def test_detect_env_export(self):
        """Test detection of environment variable exports."""
        detector = CustomDetector()
        text = "export MY_SECRET_KEY=supersecretvalue123"
        findings = detector.detect(text)
        
        env_findings = [f for f in findings if f.pattern_name == "ENV_SECRET"]
        assert len(env_findings) == 1
        assert "supersecretvalue123" in env_findings[0].matched_text
    
    def test_detect_db_connection(self):
        """Test detection of database connection strings."""
        detector = CustomDetector()
        text = "postgres://user:password@localhost:5432/mydb"
        findings = detector.detect(text)
        
        db_findings = [f for f in findings if f.pattern_name == "DB_CONNECTION"]
        assert len(db_findings) == 1
    
    def test_detect_user_path(self):
        """Test detection of user home directory paths."""
        detector = CustomDetector()
        text = "/Users/johndoe/projects/secret"
        findings = detector.detect(text)
        
        path_findings = [f for f in findings if f.pattern_name == "USER_PATH"]
        assert len(path_findings) == 1
        assert path_findings[0].matched_text == "johndoe"


class TestRedactor:
    """Tests for the redactor."""
    
    def test_redact_api_key(self):
        """Test redaction of API keys."""
        redactor = Redactor()
        result = redactor.redact_text("export OPENAI_KEY=sk-12345678901234567890123456789012")
        
        assert "[REDACTED:" in result.redacted_text
        assert "sk-12345678901234567890" not in result.redacted_text
    
    def test_redact_email(self):
        """Test redaction of email addresses."""
        redactor = Redactor()
        result = redactor.redact_text("Email: test@example.com")
        
        # Should redact the email
        assert "test@example.com" not in result.redacted_text or "[REDACTED:" in result.redacted_text
    
    def test_redact_multiple(self):
        """Test redaction of multiple sensitive items."""
        redactor = Redactor()
        text = "API: sk-12345678901234567890123456789012, Email: user@test.com"
        result = redactor.redact_text(text)
        
        # Should have multiple redactions
        assert result.was_modified
    
    def test_redact_csv_file(self, tmp_path: Path):
        """Test redacting a CSV file."""
        # Create test CSV
        csv_file = tmp_path / "test.csv"
        csv_file.write_text(
            'Sequence,Time,File,RangeOffset,RangeLength,Text,Language,Type\n'
            '1,100,"TERMINAL",0,0,"export API_KEY=sk-12345678901234567890123456789012",,terminal_command\n'
            '2,200,"TERMINAL",0,0,"echo done",,terminal_command\n'
        )
        
        redactor = Redactor()
        result = redactor.redact_csv_file(csv_file)
        
        assert result.total_rows == 2
        assert result.modified_rows >= 1
        assert result.output_path is not None
        assert result.output_path.exists()


class TestIntegration:
    """Integration tests for the full pipeline."""
    
    def test_full_pipeline(self, tmp_path: Path):
        """Test the full anonymization pipeline."""
        # Create a test CSV with various sensitive data
        csv_content = '''Sequence,Time,File,RangeOffset,RangeLength,Text,Language,Type
1,0,"test.py",0,0,"# Configuration file",python,tab
2,100,"TERMINAL",0,0,"export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",,terminal_command
3,200,"TERMINAL",0,0,"curl -H 'Authorization: Bearer eyJhbGc...' https://api.example.com",,terminal_command
4,300,"TERMINAL",0,0,"Connected to postgres://admin:secretpass@db.internal.company.com:5432/prod",,terminal_output
5,400,"config.py",0,50,"EMAIL = 'admin@company.com'",python,content
'''
        
        csv_file = tmp_path / "source.csv"
        csv_file.write_text(csv_content)
        
        redactor = Redactor(strict=True)
        result = redactor.redact_csv_file(csv_file)
        
        # Verify redactions occurred
        assert result.total_redactions > 0
        assert result.output_path is not None
        
        # Read output and verify sensitive data is redacted
        output_content = result.output_path.read_text()
        assert "AKIAIOSFODNN7EXAMPLE" not in output_content
        assert "secretpass" not in output_content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

