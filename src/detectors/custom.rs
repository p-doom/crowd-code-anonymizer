//! Custom pattern detection
//!
//! Detects paths, usernames, and other application-specific patterns.

use once_cell::sync::Lazy;
use regex::Regex;

use super::{Detector, Finding};

// Unix home directory paths
static UNIX_HOME_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"/home/[a-zA-Z][a-zA-Z0-9_-]*").unwrap()
});

// macOS user paths
static MACOS_USER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"/Users/[a-zA-Z][a-zA-Z0-9_-]*").unwrap()
});

// Windows user paths (with backslashes)
static WINDOWS_USER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"C:\\Users\\[a-zA-Z][a-zA-Z0-9_-]*").unwrap()
});

// Windows user paths (with forward slashes)
static WINDOWS_USER_FWD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"C:/Users/[a-zA-Z][a-zA-Z0-9_-]*").unwrap()
});

// SSH key comments (email-like patterns in SSH context)
static SSH_KEY_COMMENT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"ssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]+\s+([^\s]+@[^\s]+)").unwrap()
});

// Git author/committer lines
static GIT_AUTHOR_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(?:author|committer):\s*([^<]+)<([^>]+)>").unwrap()
});

/// Custom detector for application-specific patterns
pub struct CustomDetector {
    strict: bool,
}

impl CustomDetector {
    pub fn new(strict: bool) -> Self {
        Self { strict }
    }

    fn detect_with_pattern(
        &self,
        text: &str,
        pattern: &Regex,
        label: &str,
    ) -> Vec<Finding> {
        pattern
            .find_iter(text)
            .map(|m| {
                Finding::new(
                    m.start(),
                    m.end(),
                    m.as_str().to_string(),
                    label,
                    "custom",
                )
            })
            .collect()
    }
}

impl Detector for CustomDetector {
    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // User paths
        findings.extend(self.detect_with_pattern(text, &UNIX_HOME_PATTERN, "USER_PATH"));
        findings.extend(self.detect_with_pattern(text, &MACOS_USER_PATTERN, "USER_PATH"));
        findings.extend(self.detect_with_pattern(text, &WINDOWS_USER_PATTERN, "USER_PATH"));
        findings.extend(self.detect_with_pattern(text, &WINDOWS_USER_FWD_PATTERN, "USER_PATH"));

        // SSH and Git patterns (strict mode only due to potential false positives)
        if self.strict {
            // SSH key comments
            for caps in SSH_KEY_COMMENT_PATTERN.captures_iter(text) {
                if let Some(comment) = caps.get(1) {
                    findings.push(Finding::new(
                        comment.start(),
                        comment.end(),
                        comment.as_str().to_string(),
                        "SSH_KEY_COMMENT",
                        "custom",
                    ));
                }
            }

            // Git author info
            for caps in GIT_AUTHOR_PATTERN.captures_iter(text) {
                let full_match = caps.get(0).unwrap();
                findings.push(Finding::new(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    "GIT_AUTHOR",
                    "custom",
                ));
            }
        }

        findings
    }

    fn name(&self) -> &'static str {
        "custom"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unix_path() {
        let detector = CustomDetector::new(false);
        let findings = detector.detect("File at /home/johndoe/project/file.txt");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "/home/johndoe");
        assert_eq!(findings[0].label, "USER_PATH");
    }

    #[test]
    fn test_macos_path() {
        let detector = CustomDetector::new(false);
        let findings = detector.detect("Located at /Users/janedoe/Documents");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "/Users/janedoe");
    }

    #[test]
    fn test_windows_path() {
        let detector = CustomDetector::new(false);
        let findings = detector.detect(r"Open C:\Users\admin\Desktop\file.txt");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].text.contains("admin"));
    }

    #[test]
    fn test_git_author_strict() {
        let detector = CustomDetector::new(true);
        let findings = detector.detect("Author: John Doe <john@example.com>");
        assert!(!findings.is_empty());
    }
}

