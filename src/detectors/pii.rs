//! PII detection using regex patterns
//!
//! Detects email addresses, phone numbers (international format), IP addresses, SSN, IBAN.

use once_cell::sync::Lazy;
use regex::Regex;

use super::{Detector, Finding};

// Email addresses
static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b").unwrap()
});

// Phone numbers (international format only - requires + prefix)
static PHONE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\+\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b").unwrap()
});

// IPv4 addresses
static IP_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap()
});

// US Social Security Numbers
static SSN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()
});

// IBAN codes
static IBAN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b").unwrap()
});

// US ITIN (starts with 9)
static ITIN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b9\d{2}-\d{2}-\d{4}\b").unwrap()
});

// Singapore NRIC/FIN
static SG_NRIC_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[STFG]\d{7}[A-Z]\b").unwrap()
});

// Indian PAN
static IN_PAN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Z]{5}\d{4}[A-Z]\b").unwrap()
});

/// PII detector using regex patterns
pub struct PiiDetector {
    strict: bool,
}

impl PiiDetector {
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
                    "pii",
                ).with_score(score)
            })
            .collect()
    }
}

impl Detector for PiiDetector {
    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        findings.extend(self.detect_with_pattern(text, &EMAIL_PATTERN, "EMAIL", 0.9));
        findings.extend(self.detect_with_pattern(text, &PHONE_PATTERN, "PHONE", 0.8));
        findings.extend(self.detect_with_pattern(text, &IP_PATTERN, "IP_ADDRESS", 0.9));
        findings.extend(self.detect_with_pattern(text, &SSN_PATTERN, "SSN", 0.9));
        findings.extend(self.detect_with_pattern(text, &IBAN_PATTERN, "IBAN", 0.8));

        if self.strict {
            findings.extend(self.detect_with_pattern(text, &ITIN_PATTERN, "TAX_ID", 0.8));
            findings.extend(self.detect_with_pattern(text, &SG_NRIC_PATTERN, "NATIONAL_ID", 0.9));
            findings.extend(self.detect_with_pattern(text, &IN_PAN_PATTERN, "TAX_ID", 0.9));
        }

        findings
    }

    fn name(&self) -> &'static str {
        "pii"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detection() {
        let detector = PiiDetector::new(false);
        let findings = detector.detect("Contact me at john.doe@example.com for details");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, "EMAIL");
        assert_eq!(findings[0].text, "john.doe@example.com");
    }

    #[test]
    fn test_phone_international() {
        let detector = PiiDetector::new(false);
        let findings = detector.detect("Call +1-555-123-4567 or +44 20 7946 0958");
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.label == "PHONE"));
    }

    #[test]
    fn test_no_false_positive_phone() {
        let detector = PiiDetector::new(false);
        // Should NOT match floating point numbers
        let findings = detector.detect("base_pos: [0.0225279  0.00077199 0.3389144]");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ip_address() {
        let detector = PiiDetector::new(false);
        let findings = detector.detect("Server at 192.168.1.1 is down");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, "IP_ADDRESS");
    }

    #[test]
    fn test_ssn() {
        let detector = PiiDetector::new(false);
        let findings = detector.detect("SSN: 123-45-6789");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].label, "SSN");
    }
}

