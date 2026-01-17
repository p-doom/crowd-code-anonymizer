//! Secret detection using regex patterns
//!
//! Detects API keys, tokens, and credentials from various services.

use once_cell::sync::Lazy;
use regex::Regex;

use super::{Detector, Finding};

// AWS Access Key ID
static AWS_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b").unwrap()
});

// AWS Secret Access Key (40 char base64)
static AWS_SECRET_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"#).unwrap()
});

// GitHub Personal Access Token
static GITHUB_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b").unwrap()
});

// GitLab Personal Access Token
static GITLAB_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bglpat-[A-Za-z0-9\-_]{20,}\b").unwrap()
});

// Stripe API Key
static STRIPE_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(sk|pk)_(test|live)_[A-Za-z0-9]{24,}\b").unwrap()
});

// OpenAI API Key
static OPENAI_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bsk-[A-Za-z0-9]{20,}\b").unwrap()
});

// HuggingFace Token
static HF_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bhf_[A-Za-z0-9]{20,}\b").unwrap()
});

// Slack Token
static SLACK_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b").unwrap()
});

// Discord Bot Token
static DISCORD_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}\b").unwrap()
});

// Telegram Bot Token
static TELEGRAM_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b").unwrap()
});

// Twilio API Key
static TWILIO_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSK[a-f0-9]{32}\b").unwrap()
});

// SendGrid API Key
static SENDGRID_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bSG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}\b").unwrap()
});

// Mailchimp API Key
static MAILCHIMP_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[a-f0-9]{32}-us\d{1,2}\b").unwrap()
});

// NPM Token
static NPM_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap()
});

// PyPI Token
static PYPI_TOKEN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b").unwrap()
});

// Django Secret Key (django-insecure-* pattern)
static DJANGO_SECRET_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\bdjango-insecure-[A-Za-z0-9\-_!@#$%^&*()+=]{10,}\b").unwrap()
});

// JWT Token
static JWT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b").unwrap()
});

// Private Key (PEM format)
static PRIVATE_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----").unwrap()
});

// Basic Auth in URL
static BASIC_AUTH_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"://[^:]+:[^@]+@").unwrap()
});

// Generic API Key pattern (key=value with high entropy)
// Includes special characters commonly found in secrets: -_!@#$%^&*()+=
static GENERIC_KEY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(?:api[_-]?key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*['"]?([A-Za-z0-9\-_!@#$%^&*()+=]{16,})['"]?"#).unwrap()
});

/// Secret detector using regex patterns
pub struct SecretsDetector {
    strict: bool,
}

impl SecretsDetector {
    pub fn new(strict: bool) -> Self {
        Self { strict }
    }

    fn detect_with_pattern(
        &self,
        text: &str,
        pattern: &Regex,
        label: &str,
        score: f64,
    ) -> Vec<Finding> {
        pattern
            .find_iter(text)
            .map(|m| {
                Finding::new(
                    m.start(),
                    m.end(),
                    m.as_str().to_string(),
                    label,
                    "secrets",
                ).with_score(score)
            })
            .collect()
    }
}

impl Detector for SecretsDetector {
    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Cloud providers
        findings.extend(self.detect_with_pattern(text, &AWS_KEY_PATTERN, "AWS_KEY", 0.95));
        findings.extend(self.detect_with_pattern(text, &AWS_SECRET_PATTERN, "AWS_SECRET", 0.9));

        // Version control
        findings.extend(self.detect_with_pattern(text, &GITHUB_TOKEN_PATTERN, "GITHUB_TOKEN", 0.95));
        findings.extend(self.detect_with_pattern(text, &GITLAB_TOKEN_PATTERN, "GITLAB_TOKEN", 0.95));

        // Payment
        findings.extend(self.detect_with_pattern(text, &STRIPE_KEY_PATTERN, "STRIPE_KEY", 0.95));

        // AI/ML
        findings.extend(self.detect_with_pattern(text, &OPENAI_KEY_PATTERN, "OPENAI_KEY", 0.9));
        findings.extend(self.detect_with_pattern(text, &HF_TOKEN_PATTERN, "HF_TOKEN", 0.95));

        // Communication
        findings.extend(self.detect_with_pattern(text, &SLACK_TOKEN_PATTERN, "SLACK_TOKEN", 0.95));
        findings.extend(self.detect_with_pattern(text, &DISCORD_TOKEN_PATTERN, "DISCORD_TOKEN", 0.9));
        findings.extend(self.detect_with_pattern(text, &TELEGRAM_TOKEN_PATTERN, "TELEGRAM_TOKEN", 0.9));

        // Email services
        findings.extend(self.detect_with_pattern(text, &TWILIO_KEY_PATTERN, "TWILIO_KEY", 0.95));
        findings.extend(self.detect_with_pattern(text, &SENDGRID_KEY_PATTERN, "SENDGRID_KEY", 0.95));
        findings.extend(self.detect_with_pattern(text, &MAILCHIMP_KEY_PATTERN, "MAILCHIMP_KEY", 0.9));

        // Package managers
        findings.extend(self.detect_with_pattern(text, &NPM_TOKEN_PATTERN, "NPM_TOKEN", 0.95));
        findings.extend(self.detect_with_pattern(text, &PYPI_TOKEN_PATTERN, "PYPI_TOKEN", 0.95));

        // Framework secrets
        findings.extend(self.detect_with_pattern(text, &DJANGO_SECRET_PATTERN, "DJANGO_SECRET", 0.95));

        // Crypto
        findings.extend(self.detect_with_pattern(text, &JWT_PATTERN, "JWT_TOKEN", 0.85));
        findings.extend(self.detect_with_pattern(text, &PRIVATE_KEY_PATTERN, "PRIVATE_KEY", 0.99));
        findings.extend(self.detect_with_pattern(text, &BASIC_AUTH_PATTERN, "BASIC_AUTH", 0.9));

        // Generic key=value patterns (api_key=, secret=, token=, password=, etc.)
        findings.extend(self.detect_with_pattern(text, &GENERIC_KEY_PATTERN, "API_KEY", 0.7));

        findings
    }

    fn name(&self) -> &'static str {
        "secrets"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_key() {
        let detector = SecretsDetector::new(false);
        let findings = detector.detect("AWS_KEY=AKIAIOSFODNN7EXAMPLE");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.label == "AWS_KEY"));
    }

    #[test]
    fn test_github_token() {
        let detector = SecretsDetector::new(false);
        let findings = detector.detect("token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, "GITHUB_TOKEN");
    }

    #[test]
    fn test_stripe_key() {
        let detector = SecretsDetector::new(false);
        let findings = detector.detect("STRIPE_KEY=sk_live_abc123def456789012345678");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.label == "STRIPE_KEY"));
    }

    #[test]
    fn test_jwt() {
        let detector = SecretsDetector::new(false);
        let findings = detector.detect("Bearer f0KpZ3xQmN8rT2vLwJc5bH1aS6dE9uYgX7.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.label == "JWT_TOKEN"));
    }

    #[test]
    fn test_private_key() {
        let detector = SecretsDetector::new(false);
        let findings = detector.detect("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, "PRIVATE_KEY");
    }
}

