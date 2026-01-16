"""
Crowd Pilot Anonymizer - Robust CSV anonymization for software engineering traces.

Combines multiple detection layers:
- detect-secrets: API keys, tokens, credentials
- Presidio: PII (emails, names, phones, IPs)
- Custom recognizers: Domain-specific patterns
"""

__version__ = "0.1.0"

