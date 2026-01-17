//! High-entropy string detection
//!
//! Detects random-looking strings (API keys, tokens, hashes, UUIDs, etc.)
//! using Shannon entropy calculation and camelCase filtering.

use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

use super::{Detector, Finding};

/// Match alphanumeric strings of 16+ chars (with common separators and special chars)
/// Includes special characters commonly found in secrets: -_!@#$%^&*()
/// Note: excludes = to avoid matching KEY=value as a single unit
/// The pattern requires start/end with alphanumeric to avoid matching trailing separators
static HIGH_ENTROPY_CANDIDATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b[A-Za-z0-9][A-Za-z0-9_\-!@#$%^&*()]{14,}[A-Za-z0-9]\b").unwrap()
});

/// Entropy threshold in bits per character
const ENTROPY_THRESHOLD: f64 = 3.0;

/// Minimum length for entropy detection
const MIN_LENGTH: usize = 16;

/// Minimum average segment length for camelCase (chars between uppercase boundaries)
const MIN_AVG_SEGMENT_LENGTH: f64 = 4.0;

/// Check if string looks like camelCase code identifier
fn is_camel_case_identifier(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return false;
    }
    
    // Find positions of uppercase letters (these are word boundaries in camelCase)
    let mut boundaries: Vec<usize> = vec![0]; // Start is implicit boundary
    for (i, c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() {
            boundaries.push(i);
        }
    }
    boundaries.push(chars.len()); // End is implicit boundary
    
    // Need at least 1 uppercase letter (2 "words" = 3 boundaries including start/end)
    // e.g., "workspaceFolders" has boundaries [0, 9, 16] = 3
    if boundaries.len() < 3 {
        return false;
    }
    
    // Calculate average segment length between uppercase letters
    let mut total_length = 0;
    let mut segment_count = 0;
    for i in 1..boundaries.len() {
        let seg_len = boundaries[i] - boundaries[i - 1];
        if seg_len > 0 {
            total_length += seg_len;
            segment_count += 1;
        }
    }
    
    if segment_count == 0 {
        return false;
    }
    
    let avg_segment_len = total_length as f64 / segment_count as f64;
    
    // Real camelCase has longer segments (words like "workspace", "Folders")
    // Random strings have short chaotic segments
    avg_segment_len >= MIN_AVG_SEGMENT_LENGTH
}

/// Check if a string segment looks like hex (mostly 0-9 and a-f)
fn is_hex_like(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let hex_chars = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
    // If >80% of chars are hex digits, it's likely a hash/UUID segment
    (hex_chars as f64 / s.len() as f64) > 0.8
}

/// Check if string contains secret-related keywords that should NOT be filtered
fn contains_secret_keywords(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    let keywords = [
        "secret", "insecure", "password", "passwd", "token", "key", "credential",
        "auth", "private", "apikey", "api_key",
    ];
    keywords.iter().any(|kw| lower.contains(kw))
}

/// Check if string looks like snake_case or kebab-case identifier
fn is_snake_or_kebab_case(s: &str) -> bool {
    if contains_secret_keywords(s) {
        return false;
    }
    
    // Check for snake_case: foo_bar_baz
    let underscore_segments: Vec<&str> = s.split('_').filter(|seg| !seg.is_empty()).collect();
    if underscore_segments.len() >= 2 {
        // Exclude if most segments look like hex (UUIDs, hashes)
        let hex_segments = underscore_segments.iter().filter(|seg| is_hex_like(seg)).count();
        if hex_segments > underscore_segments.len() / 2 {
            return false;
        }
        
        // If all segments are lowercase letters (allow some with numbers like v1)
        let valid_segments = underscore_segments.iter()
            .filter(|seg| seg.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
            .count();
        if valid_segments >= 2 && valid_segments == underscore_segments.len() {
            return true;
        }
    }
    
    // Check for kebab-case: foo-bar-baz
    let dash_segments: Vec<&str> = s.split('-').filter(|seg| !seg.is_empty()).collect();
    if dash_segments.len() >= 2 {
        // Exclude if most segments look like hex (UUIDs, hashes)
        let hex_segments = dash_segments.iter().filter(|seg| is_hex_like(seg)).count();
        if hex_segments > dash_segments.len() / 2 {
            return false;
        }
        
        // If all segments are lowercase letters or digits
        let valid_segments = dash_segments.iter()
            .filter(|seg| seg.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
            .count();
        if valid_segments >= 2 && valid_segments == dash_segments.len() {
            return true;
        }
    }
    
    false
}

/// Check if string looks like a code identifier (camelCase, snake_case, or kebab-case)
fn is_likely_code_identifier(s: &str) -> bool {
    if is_camel_case_identifier(s) {
        return true;
    }
    
    if is_snake_or_kebab_case(s) {
        return true;
    }
    
    false
}

/// Calculate Shannon entropy of a string (bits per character)
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let len = s.len() as f64;
    
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let entropy: f64 = freq
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum();

    entropy
}

/// High-entropy string detector
///
/// Identifies strings that appear random based on character distribution.
pub struct EntropyDetector;

impl EntropyDetector {
    pub fn new() -> Self {
        Self
    }
}

impl Default for EntropyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for EntropyDetector {
    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for m in HIGH_ENTROPY_CANDIDATE.find_iter(text) {
            let matched_str = m.as_str();
            
            if matched_str.len() < MIN_LENGTH {
                continue;
            }

            if is_likely_code_identifier(matched_str) {
                continue;
            }

            let entropy = shannon_entropy(matched_str);

            if entropy >= ENTROPY_THRESHOLD {
                findings.push(Finding::new(
                    m.start(),
                    m.end(),
                    matched_str.to_string(),
                    "HIGH_ENTROPY",
                    "entropy",
                ).with_score(entropy / 4.0));
            }
        }

        findings
    }

    fn name(&self) -> &'static str {
        "entropy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_random() {
        let entropy = shannon_entropy("a1b2c3d4e5f6g7h8");
        assert!(entropy > 3.0, "Random hex should have high entropy: {}", entropy);
    }

    #[test]
    fn test_shannon_entropy_repeated() {
        let entropy = shannon_entropy("aaaaaaaaaaaaaaaa");
        assert!(entropy < 0.1, "Repeated chars should have near-zero entropy: {}", entropy);
    }

    #[test]
    fn test_shannon_entropy_pattern() {
        let entropy = shannon_entropy("abababababababab");
        assert!(entropy < 2.0, "Simple pattern should have low entropy: {}", entropy);
    }

    #[test]
    fn test_camel_case_identifier() {
        assert!(is_camel_case_identifier("onChangeSubscription")); // on|Change|Subscription
        assert!(is_camel_case_identifier("handleUserInputEvent")); // handle|User|Input|Event
        assert!(is_camel_case_identifier("getEditorFileName")); // get|Editor|File|Name
        assert!(is_camel_case_identifier("workspaceFolders")); // workspace|Folders
        assert!(is_camel_case_identifier("finalizeRecording")); // finalize|Recording
        assert!(is_camel_case_identifier("processedChanges")); // processed|Changes
        assert!(is_camel_case_identifier("onChange")); // on|Change - 2 segments, avg=4
        
        assert!(!is_camel_case_identifier("lowercase")); // no uppercase
        assert!(!is_camel_case_identifier("UPPERCASE")); // no lowercase segments
        
        assert!(!is_camel_case_identifier("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"));
        assert!(!is_camel_case_identifier("AbCdEfGhIjKlMnOp")); // single char segments
    }

    #[test]
    fn test_snake_or_kebab_case() {
        // snake_case
        assert!(is_snake_or_kebab_case("on_change"));
        assert!(is_snake_or_kebab_case("atari_v1_release"));
        assert!(is_snake_or_kebab_case("handle_user_input"));
        
        assert!(is_snake_or_kebab_case("circle-large-filled"));
        assert!(is_snake_or_kebab_case("my-component-name"));
        
        assert!(!is_snake_or_kebab_case("singleword"));
        
        assert!(!is_snake_or_kebab_case("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"));
        
        assert!(!is_snake_or_kebab_case("1426dccf-4f0c-4bba-b6e3-036dc50fcf41"));
        assert!(!is_snake_or_kebab_case("63ab949f_310c906e_eb4b86a8"));
    }

    #[test]
    fn test_is_likely_code_identifier() {
        assert!(is_likely_code_identifier("onChangeSubscription"));
        assert!(is_likely_code_identifier("workspaceFolders"));
        assert!(is_likely_code_identifier("finalizeRecording"));
        assert!(is_likely_code_identifier("processedChanges"));
        assert!(is_likely_code_identifier("getEditorFileName"));
        
        assert!(is_likely_code_identifier("on_change_subscription"));
        assert!(is_likely_code_identifier("atari_v1_release"));
        
        assert!(is_likely_code_identifier("circle-large-filled"));
        
        assert!(!is_likely_code_identifier("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"));
        assert!(!is_likely_code_identifier("abc123def456ghi789"));
        assert!(!is_likely_code_identifier("AbCdEfGhIjKlMnOp"));
    }

    #[test]
    fn test_detect_api_key() {
        let detector = EntropyDetector::new();
        let findings = detector.detect("API_KEY=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");
        assert!(!findings.is_empty(), "Should detect HF token");
        assert_eq!(findings[0].label, "HIGH_ENTROPY");
    }

    #[test]
    fn test_detect_uuid() {
        let detector = EntropyDetector::new();
        let findings = detector.detect("id: 1426dccf-4f0c-4bba-b6e3-036dc50fcf41");
        assert!(!findings.is_empty(), "Should detect UUID");
    }

    #[test]
    fn test_detect_sha256() {
        let detector = EntropyDetector::new();
        let findings = detector.detect("hash: 63ab949f310c906eeb4b86a8885004378aa8f93895ccb68e745b5c6d64c408a6");
        assert!(!findings.is_empty(), "Should detect SHA256");
    }

    #[test]
    fn test_no_detect_camel_case() {
        let detector = EntropyDetector::new();
        // Should NOT detect camelCase code identifiers
        let findings = detector.detect("onChangeSubscription");
        assert!(findings.is_empty(), "Should not detect camelCase identifier");
        
        let findings = detector.detect("handleUserInputEvent");
        assert!(findings.is_empty(), "Should not detect camelCase identifier");
        
        let findings = detector.detect("getEditorFileNameFromPath");
        assert!(findings.is_empty(), "Should not detect camelCase identifier");
    }

    #[test]
    fn test_no_detect_snake_case() {
        let detector = EntropyDetector::new();
        // Should NOT detect snake_case code identifiers
        let findings = detector.detect("on_change_subscription_handler");
        assert!(findings.is_empty(), "Should not detect snake_case identifier");
    }

    #[test]
    fn test_no_detect_normal_word() {
        let detector = EntropyDetector::new();
        let findings = detector.detect("The quick brown fox jumps over the lazy dog");
        assert!(findings.is_empty(), "Should not detect normal words");
    }

    #[test]
    fn test_no_detect_short_string() {
        let detector = EntropyDetector::new();
        let findings = detector.detect("key=abc123");
        assert!(findings.is_empty(), "Should not detect short strings");
    }
}

