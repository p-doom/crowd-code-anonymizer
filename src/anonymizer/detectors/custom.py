"""Custom regex-based recognizers for domain-specific patterns."""

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass
class CustomFinding:
    """Represents a finding from custom pattern matching."""
    
    pattern_name: str
    matched_text: str
    start: int
    end: int
    
    @property
    def redaction_label(self) -> str:
        """Get the redaction label for this finding."""
        return self.pattern_name


@dataclass  
class PatternDefinition:
    """Definition of a custom detection pattern."""
    
    name: str
    pattern: Pattern[str]
    description: str
    # Group index to extract (0 = whole match, 1+ = capture group)
    extract_group: int = 0


class CustomDetector:
    """Detect sensitive data using custom regex patterns."""
    
    # Default patterns for common secrets not covered by detect-secrets
    DEFAULT_PATTERNS: list[PatternDefinition] = [
        # OpenAI API keys (newer format)
        PatternDefinition(
            name="OPENAI_KEY",
            pattern=re.compile(r'sk-[a-zA-Z0-9]{20,}'),
            description="OpenAI API key",
        ),
        # Anthropic API keys
        PatternDefinition(
            name="ANTHROPIC_KEY",
            pattern=re.compile(r'sk-ant-[a-zA-Z0-9\-]{20,}'),
            description="Anthropic API key",
        ),
        # Generic API key in environment variable export
        PatternDefinition(
            name="ENV_SECRET",
            pattern=re.compile(
                r'export\s+\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|API|AUTH)\w*\s*=\s*[\'"]?([^\s\'"]+)[\'"]?',
                re.IGNORECASE
            ),
            description="Environment variable with secret",
            extract_group=1,
        ),
        # Bearer token in curl/http commands
        PatternDefinition(
            name="BEARER_TOKEN",
            pattern=re.compile(
                r'[Bb]earer\s+([a-zA-Z0-9\-_.]+)',
            ),
            description="Bearer authentication token",
            extract_group=1,
        ),
        # Authorization header values
        PatternDefinition(
            name="AUTH_HEADER",
            pattern=re.compile(
                r'[Aa]uthorization[:\s]+[\'"]?([a-zA-Z0-9\-_.=+/]+)[\'"]?',
            ),
            description="Authorization header value",
            extract_group=1,
        ),
        # Database connection strings
        PatternDefinition(
            name="DB_CONNECTION",
            pattern=re.compile(
                r'(?:postgres|postgresql|mysql|mongodb|redis|amqp|rabbitmq)://[^\s\'"<>]+',
                re.IGNORECASE
            ),
            description="Database connection string",
        ),
        # Password in connection strings or URLs
        PatternDefinition(
            name="URL_PASSWORD",
            pattern=re.compile(
                r'://([^:]+):([^@]+)@',
            ),
            description="Password in URL",
            extract_group=2,
        ),
        # Generic password assignment
        PatternDefinition(
            name="PASSWORD",
            pattern=re.compile(
                r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'"]+)[\'"]?',
                re.IGNORECASE
            ),
            description="Password value",
            extract_group=1,
        ),
        # SSH private key content
        PatternDefinition(
            name="SSH_PRIVATE_KEY",
            pattern=re.compile(
                r'-----BEGIN\s+(?:RSA\s+|DSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----',
            ),
            description="SSH/RSA private key header",
        ),
        # PGP private key
        PatternDefinition(
            name="PGP_PRIVATE_KEY",
            pattern=re.compile(
                r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----',
            ),
            description="PGP private key header",
        ),
        # AWS Access Key ID (backup pattern)
        PatternDefinition(
            name="AWS_ACCESS_KEY",
            pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
            description="AWS Access Key ID",
        ),
        # AWS Secret Access Key pattern
        PatternDefinition(
            name="AWS_SECRET_KEY", 
            pattern=re.compile(
                r'(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*[\'"]?([a-zA-Z0-9/+=]{40})[\'"]?',
                re.IGNORECASE
            ),
            description="AWS Secret Access Key",
            extract_group=1,
        ),
        # Google Cloud API key
        PatternDefinition(
            name="GCP_API_KEY",
            pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
            description="Google Cloud API key",
        ),
        # Slack webhook URL
        PatternDefinition(
            name="SLACK_WEBHOOK",
            pattern=re.compile(
                r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
            ),
            description="Slack webhook URL",
        ),
        # Discord webhook URL
        PatternDefinition(
            name="DISCORD_WEBHOOK",
            pattern=re.compile(
                r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',
            ),
            description="Discord webhook URL",
        ),
        # Hugging Face token
        PatternDefinition(
            name="HF_TOKEN",
            pattern=re.compile(r'hf_[a-zA-Z0-9]{34}'),
            description="Hugging Face API token",
        ),
        # Replicate API token
        PatternDefinition(
            name="REPLICATE_TOKEN",
            pattern=re.compile(r'r8_[a-zA-Z0-9]{40}'),
            description="Replicate API token",
        ),
        # Internal hostnames (common patterns)
        PatternDefinition(
            name="INTERNAL_HOST",
            pattern=re.compile(
                r'\b(?:internal|staging|dev|prod|admin|private)[.-][a-z0-9.-]+\.[a-z]{2,}\b',
                re.IGNORECASE
            ),
            description="Internal hostname",
        ),
        # User home directory paths (Unix)
        PatternDefinition(
            name="USER_PATH",
            pattern=re.compile(
                r'/(?:Users|home)/([a-zA-Z0-9_-]+)/',
            ),
            description="User home directory path",
            extract_group=1,
        ),
        # Windows user path
        PatternDefinition(
            name="WINDOWS_USER_PATH",
            pattern=re.compile(
                r'C:\\Users\\([a-zA-Z0-9_-]+)\\',
                re.IGNORECASE
            ),
            description="Windows user directory path",
            extract_group=1,
        ),
    ]
    
    def __init__(self, strict: bool = False, additional_patterns: list[PatternDefinition] | None = None):
        """Initialize the custom detector.
        
        Args:
            strict: If True, use all patterns including potentially noisy ones
            additional_patterns: Extra patterns to include
        """
        self.strict = strict
        self.patterns = list(self.DEFAULT_PATTERNS)
        
        if additional_patterns:
            self.patterns.extend(additional_patterns)
    
    def detect(self, text: str) -> list[CustomFinding]:
        """Detect sensitive data using custom patterns.
        
        Args:
            text: Text to scan
            
        Returns:
            List of CustomFinding objects
        """
        findings: list[CustomFinding] = []
        
        if not text:
            return findings
        
        for pattern_def in self.patterns:
            try:
                for match in pattern_def.pattern.finditer(text):
                    # Extract the relevant group
                    if pattern_def.extract_group > 0 and pattern_def.extract_group <= len(match.groups()):
                        matched_text = match.group(pattern_def.extract_group)
                        # Calculate position of the extracted group
                        start = match.start(pattern_def.extract_group)
                        end = match.end(pattern_def.extract_group)
                    else:
                        matched_text = match.group(0)
                        start = match.start()
                        end = match.end()
                    
                    if matched_text:  # Skip empty matches
                        findings.append(CustomFinding(
                            pattern_name=pattern_def.name,
                            matched_text=matched_text,
                            start=start,
                            end=end,
                        ))
            except Exception:
                # Skip patterns that fail
                continue
        
        return findings
    
    def detect_multiline(self, text: str) -> list[CustomFinding]:
        """Detect sensitive data in multiline text.
        
        Args:
            text: Multiline text to scan
            
        Returns:
            List of CustomFinding objects
        """
        return self.detect(text)

