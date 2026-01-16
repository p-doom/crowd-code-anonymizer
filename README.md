# Crowd Pilot Anonymizer

A robust CSV anonymization tool for crowd-sourced software engineering traces. Combines multiple detection layers for defense-in-depth:

1. **detect-secrets** - API keys, tokens, credentials, high-entropy strings
2. **Presidio** - PII (emails, names, phone numbers, IPs, credit cards)
3. **Custom recognizers** - Domain-specific patterns (OpenAI keys, connection strings, etc.)

## Installation

```bash
# Clone the repository
git clone https://github.com/p-doom/crowd-pilot-anonymizer.git
cd crowd-pilot-anonymizer

# Install with pip (editable mode for development)
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

## Usage

```bash
# Anonymize a single CSV file
anonymize ./source.csv -o ./anonymized.csv

# Anonymize all CSVs in a directory recursively
anonymize ./crowd-code-exports/ --recursive

# Dry-run mode (show what would be redacted without modifying)
anonymize ./source.csv --dry-run

# Generate a detailed JSON report of all redactions
anonymize ./source.csv --report report.json

# More aggressive detection (lower thresholds)
anonymize ./source.csv --strict
```

## CSV Format

This tool is designed for CSVs exported by [crowd-code](https://github.com/p-doom/crowd-code) with the format:

```
Sequence,Time,File,RangeOffset,RangeLength,Text,Language,Type
```

The `Type` column indicates the source of the data:
- `terminal_command` - Shell commands (highest secret risk)
- `terminal_output` - Command output (high risk)
- `content` - File edits (medium risk)
- `tab` - Full file content on tab switch (medium risk)

## Detection Patterns

### detect-secrets (built-in)
- AWS keys, Azure keys, GCP keys
- GitHub/GitLab tokens
- JWT tokens
- Private keys (RSA, SSH, PGP)
- High-entropy base64/hex strings
- Slack tokens, Stripe keys, Twilio keys
- And many more...

### Presidio (built-in)
- Email addresses
- Phone numbers
- IP addresses (v4 and v6)
- Credit card numbers
- Person names (via NER)
- Social Security Numbers

### Custom Recognizers
- OpenAI API keys (`sk-...`)
- Anthropic keys (`sk-ant-...`)
- Database connection strings (postgres://, mysql://, mongodb://)
- Environment variable exports with secrets
- Bearer tokens in curl commands

## Output

Anonymized CSVs replace detected sensitive data with redaction markers:

```
[REDACTED:API_KEY]
[REDACTED:EMAIL]
[REDACTED:SECRET]
```

The optional JSON report includes:
- Total findings per detection layer
- Breakdown by entity type
- Location of each redaction (row, column, position)

## License

MIT

