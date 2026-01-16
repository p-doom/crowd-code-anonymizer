"""Secret detection layer using detect-secrets library."""

from dataclasses import dataclass
from typing import Any

from detect_secrets import main as detect_secrets_main
from detect_secrets.core import scan
from detect_secrets.settings import transient_settings


@dataclass
class SecretFinding:
    """Represents a detected secret."""
    
    secret_type: str
    secret_value: str
    start: int
    end: int
    line_number: int | None = None
    
    @property
    def redaction_label(self) -> str:
        """Get the redaction label for this finding."""
        # Map detect-secrets types to simpler labels
        type_map = {
            "AWSKeyDetector": "AWS_KEY",
            "AzureStorageKeyDetector": "AZURE_KEY",
            "BasicAuthDetector": "BASIC_AUTH",
            "CloudantDetector": "CLOUDANT",
            "DiscordBotTokenDetector": "DISCORD_TOKEN",
            "GitHubTokenDetector": "GITHUB_TOKEN",
            "GitLabTokenDetector": "GITLAB_TOKEN",
            "Base64HighEntropyString": "HIGH_ENTROPY",
            "HexHighEntropyString": "HIGH_ENTROPY",
            "IbmCloudIamDetector": "IBM_IAM",
            "IbmCosHmacDetector": "IBM_HMAC",
            "JwtTokenDetector": "JWT_TOKEN",
            "KeywordDetector": "SECRET",
            "MailchimpDetector": "MAILCHIMP",
            "NpmDetector": "NPM_TOKEN",
            "OpenAIDetector": "OPENAI_KEY",
            "PrivateKeyDetector": "PRIVATE_KEY",
            "PypiTokenDetector": "PYPI_TOKEN",
            "SendGridDetector": "SENDGRID",
            "SlackDetector": "SLACK_TOKEN",
            "SoftlayerDetector": "SOFTLAYER",
            "SquareOAuthDetector": "SQUARE_OAUTH",
            "StripeDetector": "STRIPE_KEY",
            "TelegramBotTokenDetector": "TELEGRAM_TOKEN",
            "TwilioKeyDetector": "TWILIO_KEY",
        }
        return type_map.get(self.secret_type, "SECRET")


class SecretsDetector:
    """Detect secrets using the detect-secrets library."""
    
    def __init__(self, strict: bool = False, min_length: int = 16):
        """Initialize the secrets detector.
        
        Args:
            strict: If True, use more aggressive detection settings
            min_length: Minimum length for detected secrets
        """
        self.strict = strict
        self.min_length = min_length
        self._configure_settings()
    
    def _configure_settings(self) -> None:
        """Configure detect-secrets settings."""
        # Base plugins to use
        self.plugins = [
            {"name": "AWSKeyDetector"},
            {"name": "AzureStorageKeyDetector"},
            {"name": "BasicAuthDetector"},
            {"name": "CloudantDetector"},
            {"name": "DiscordBotTokenDetector"},
            {"name": "GitHubTokenDetector"},
            {"name": "GitLabTokenDetector"},
            {"name": "IbmCloudIamDetector"},
            {"name": "IbmCosHmacDetector"},
            {"name": "JwtTokenDetector"},
            {"name": "MailchimpDetector"},
            {"name": "NpmDetector"},
            {"name": "OpenAIDetector"},
            {"name": "PrivateKeyDetector"},
            {"name": "PypiTokenDetector"},
            {"name": "SendGridDetector"},
            {"name": "SlackDetector"},
            {"name": "SoftlayerDetector"},
            {"name": "SquareOAuthDetector"},
            {"name": "StripeDetector"},
            {"name": "TelegramBotTokenDetector"},
            {"name": "TwilioKeyDetector"},
        ]
        
        # High entropy detection
        entropy_limit = 5.5 if self.strict else 6.0
        self.plugins.extend([
            {"name": "Base64HighEntropyString", "limit": entropy_limit},
            {"name": "HexHighEntropyString", "limit": entropy_limit},
        ])
        
        # Keyword detector for common secret patterns
        # Only include in strict mode as it can be noisy
        if self.strict:
            self.plugins.append({
                "name": "KeywordDetector",
                "keyword_exclude": None,
            })
    
    def detect(self, text: str) -> list[SecretFinding]:
        """Detect secrets in the given text.
        
        Args:
            text: Text to scan for secrets
            
        Returns:
            List of SecretFinding objects
        """
        findings: list[SecretFinding] = []
        
        if not text or not text.strip():
            return findings
        
        try:
            with transient_settings({"plugins_used": self.plugins}):
                # Scan the text as if it were file content
                secrets = scan.scan_line(text)
                
                for secret in secrets:
                    # Get the secret value from the text
                    secret_value = secret.secret_value or ""
                    
                    # Find position in text
                    start = text.find(secret_value) if secret_value else -1
                    end = start + len(secret_value) if start >= 0 else -1
                    
                    if start >= 0 and len(secret_value) >= self.min_length:
                        findings.append(SecretFinding(
                            secret_type=secret.type,
                            secret_value=secret_value,
                            start=start,
                            end=end,
                        ))
        except Exception:
            # If detect-secrets fails, return empty list
            # Don't let detection errors stop the pipeline
            pass
        
        return findings
    
    def detect_multiline(self, text: str) -> list[SecretFinding]:
        """Detect secrets in multiline text, tracking line positions.
        
        Args:
            text: Multiline text to scan
            
        Returns:
            List of SecretFinding objects with line numbers
        """
        findings: list[SecretFinding] = []
        
        if not text:
            return findings
        
        lines = text.split('\n')
        current_offset = 0
        
        for line_num, line in enumerate(lines, start=1):
            line_findings = self.detect(line)
            
            for finding in line_findings:
                # Adjust positions to absolute offsets
                if finding.start >= 0:
                    finding.start += current_offset
                    finding.end += current_offset
                finding.line_number = line_num
                findings.append(finding)
            
            current_offset += len(line) + 1  # +1 for newline
        
        return findings
