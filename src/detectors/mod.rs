//! Detection modules for sensitive data identification

pub mod pii;
pub mod secrets;
pub mod names;
pub mod custom;
pub mod entropy;

use std::fmt;

/// A detected finding with position and metadata
#[derive(Debug, Clone)]
pub struct Finding {
    /// Start position in text (byte offset)
    pub start: usize,
    /// End position in text (byte offset)
    pub end: usize,
    /// The matched text
    pub text: String,
    /// Label for the finding type
    pub label: String,
    /// Source detector name
    pub source: String,
    /// Confidence score (0.0-1.0)
    pub score: f64,
}

impl Finding {
    pub fn new(start: usize, end: usize, text: String, label: &str, source: &str) -> Self {
        Self {
            start,
            end,
            text,
            label: label.to_string(),
            source: source.to_string(),
            score: 1.0,
        }
    }

    pub fn with_score(mut self, score: f64) -> Self {
        self.score = score;
        self
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] '{}' at {}-{}", self.label, self.text, self.start, self.end)
    }
}

/// Trait for detectors
pub trait Detector: Send + Sync {
    /// Detect sensitive data in the given text
    fn detect(&self, text: &str) -> Vec<Finding>;
    
    /// Name of this detector
    fn name(&self) -> &'static str;
}

// Re-exports
pub use pii::PiiDetector;
pub use secrets::SecretsDetector;
pub use names::NameDetector;
pub use custom::CustomDetector;
pub use entropy::EntropyDetector;

