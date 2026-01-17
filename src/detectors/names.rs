//! Name detection using dictionary lookups
//!
//! Loads first and last names from JSON files (from names-dataset) and detects
//! full names using positional anchor matching:
//! - Match if first word is in first_names (top-1000 in any country), OR
//! - Match if last word is in last_names (top-1000 in any country)

use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

use super::{Detector, Finding};

/// Pattern to match potential names: Two title-cased words
static NAME_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b").unwrap()
});

/// Maximum rank threshold (top 1000 names in any country)
const MAX_RANK: u32 = 1000;

/// Name entry from the JSON dataset
#[derive(Debug, Deserialize)]
struct NameEntry {
    #[serde(default)]
    rank: std::collections::HashMap<String, u32>,
}

/// Name detector using dictionary lookups
pub struct NameDetector {
    first_names: HashSet<String>,
    last_names: HashSet<String>,
}

impl NameDetector {
    /// Create a new name detector, loading data from the specified directory
    pub fn new(names_dir: Option<&Path>) -> Result<Self> {
        let (first_names, last_names) = if let Some(dir) = names_dir {
            load_names_from_dir(dir)?
        } else {
            // Try default locations
            let default_paths = [
                Path::new("names-data"),
                Path::new("/usr/share/names-dataset"),
                Path::new("~/.local/share/names-dataset"),
            ];
            
            let mut loaded = None;
            for path in &default_paths {
                if path.exists() {
                    if let Ok(names) = load_names_from_dir(path) {
                        loaded = Some(names);
                        break;
                    }
                }
            }
            
            loaded.unwrap_or_else(|| {
                eprintln!("Warning: Name dataset not found, name detection disabled");
                (HashSet::new(), HashSet::new())
            })
        };

        Ok(Self {
            first_names,
            last_names,
        })
    }

    /// Create an empty detector (for testing or when dataset unavailable)
    pub fn empty() -> Self {
        Self {
            first_names: HashSet::new(),
            last_names: HashSet::new(),
        }
    }

    /// Normalize a name: title case + strip accents
    fn normalize_name(name: &str) -> String {
        let title_case: String = name
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == 0 {
                    c.to_uppercase().next().unwrap_or(c)
                } else {
                    c.to_lowercase().next().unwrap_or(c)
                }
            })
            .collect();

        // Strip accents using NFD decomposition
        title_case
            .nfd()
            .filter(|c| !c.is_mark_nonspacing())
            .collect()
    }
}

impl Detector for NameDetector {
    fn detect(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if self.first_names.is_empty() && self.last_names.is_empty() {
            return findings;
        }

        for caps in NAME_PATTERN.captures_iter(text) {
            let full_match = caps.get(0).unwrap();
            let first_raw = caps.get(1).unwrap().as_str();
            let last_raw = caps.get(2).unwrap().as_str();

            // Check title case first (fast path)
            let first_title = first_raw.to_string();
            let last_title = last_raw.to_string();

            let mut first_is_firstname = self.first_names.contains(&first_title);
            let mut last_is_lastname = self.last_names.contains(&last_title);

            // Try normalized version if title case didn't match
            if !first_is_firstname {
                let normalized = Self::normalize_name(first_raw);
                first_is_firstname = self.first_names.contains(&normalized);
            }

            if !last_is_lastname {
                let normalized = Self::normalize_name(last_raw);
                last_is_lastname = self.last_names.contains(&normalized);
            }

            // Positional anchor: match if first word is a known first name OR last word is a known last name
            if first_is_firstname || last_is_lastname {
                findings.push(Finding::new(
                    full_match.start(),
                    full_match.end(),
                    full_match.as_str().to_string(),
                    "PERSON_NAME",
                    "names",
                ));
            }
        }

        findings
    }

    fn name(&self) -> &'static str {
        "names"
    }
}

/// Load names from a directory containing first_names.json and last_names.json
fn load_names_from_dir(dir: &Path) -> Result<(HashSet<String>, HashSet<String>)> {
    let first_names_path = dir.join("first_names.json");
    let last_names_path = dir.join("last_names.json");

    let first_names = load_names_file(&first_names_path)
        .with_context(|| format!("Failed to load {}", first_names_path.display()))?;
    
    let last_names = load_names_file(&last_names_path)
        .with_context(|| format!("Failed to load {}", last_names_path.display()))?;

    Ok((first_names, last_names))
}

/// Load and filter names from a JSON file
fn load_names_file(path: &Path) -> Result<HashSet<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    
    let data: std::collections::HashMap<String, NameEntry> = serde_json::from_reader(reader)?;
    
    let mut names = HashSet::new();
    
    for (name, entry) in data {
        // Check if any country has this name in top-K
        let is_common = entry.rank.values().any(|&rank| rank <= MAX_RANK);
        
        if is_common {
            // Add title case version
            let title_name = name
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i == 0 {
                        c.to_uppercase().next().unwrap_or(c)
                    } else {
                        c.to_lowercase().next().unwrap_or(c)
                    }
                })
                .collect::<String>();
            
            names.insert(title_name.clone());
            
            // Also add normalized version (without accents)
            let normalized: String = title_name
                .nfd()
                .filter(|c| !c.is_mark_nonspacing())
                .collect();
            
            if normalized != title_name {
                names.insert(normalized);
            }
        }
    }

    Ok(names)
}

// Trait for checking if a character is a nonspacing mark
trait IsMarkNonspacing {
    fn is_mark_nonspacing(&self) -> bool;
}

impl IsMarkNonspacing for char {
    fn is_mark_nonspacing(&self) -> bool {
        matches!(unicode_normalization::char::decompose_canonical(*self, |_| {}), ())
            && self.is_alphabetic() == false
            && *self != ' '
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detector() -> NameDetector {
        let mut first_names = HashSet::new();
        let mut last_names = HashSet::new();
        
        // Add some test names
        first_names.insert("John".to_string());
        first_names.insert("Franz".to_string());
        first_names.insert("Maria".to_string());
        
        last_names.insert("Smith".to_string());
        last_names.insert("Nguyen".to_string());
        last_names.insert("Garcia".to_string());

        NameDetector {
            first_names,
            last_names,
        }
    }

    #[test]
    fn test_simple_name() {
        let detector = make_detector();
        let findings = detector.detect("Hello John Smith, how are you?");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "John Smith");
    }

    #[test]
    fn test_positional_anchor_first() {
        let detector = make_detector();
        // Franz is a known first name, Srambical is not in dataset
        let findings = detector.detect("Contact Franz Srambical for details");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "Franz Srambical");
    }

    #[test]
    fn test_positional_anchor_last() {
        let detector = make_detector();
        // Nguyen is a known last name
        let findings = detector.detect("Contact Alfred Nguyen for details");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "Alfred Nguyen");
    }

    #[test]
    fn test_no_match_code() {
        let detector = make_detector();
        // These are not names
        let findings = detector.detect("Add Node to the Button Click handler");
        assert!(findings.is_empty());
    }
}

