//! Interactive review mode
//!
//! Allows users to accept or reject redactions interactively using arrow keys.

use std::collections::HashMap;
use std::io::{self, Write};

use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent},
    execute,
    terminal::{self, ClearType},
};

use crate::redactor::{FileRedactionResult, Redaction};

/// Review session tracking decisions
pub struct ReviewSession {
    /// Cache of decisions: (original_text, label) -> accepted
    decisions: HashMap<(String, String), bool>,
}

impl ReviewSession {
    pub fn new() -> Self {
        Self {
            decisions: HashMap::new(),
        }
    }

    /// Review redactions in a file result
    pub fn review_file(&mut self, result: &mut FileRedactionResult) -> Result<()> {
        if result.redactions.is_empty() {
            return Ok(());
        }

        // Filter to only new redactions (not in cache)
        let new_redactions: Vec<usize> = result.redactions
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let key = (r.original_text.clone(), r.label.clone());
                !self.decisions.contains_key(&key)
            })
            .map(|(i, _)| i)
            .collect();

        if new_redactions.is_empty() {
            // Apply cached decisions
            for redaction in &mut result.redactions {
                let key = (redaction.original_text.clone(), redaction.label.clone());
                if let Some(&accepted) = self.decisions.get(&key) {
                    redaction.accepted = accepted;
                }
            }
            return Ok(());
        }

        // Enable raw mode for keyboard input
        terminal::enable_raw_mode()?;
        let _guard = RawModeGuard;

        let total = new_redactions.len();
        let mut current = 0;

        while current < new_redactions.len() {
            let idx = new_redactions[current];
            let redaction = &result.redactions[idx];

            self.display_redaction(redaction, current + 1, total, &result.input_path)?;

            // Wait for input
            match self.get_user_input()? {
                ReviewAction::Accept => {
                    self.cache_decision(redaction, true);
                    current += 1;
                }
                ReviewAction::Reject => {
                    self.cache_decision(redaction, false);
                    current += 1;
                }
                ReviewAction::Redo => {
                    if current > 0 {
                        // Uncache previous decision
                        let prev_idx = new_redactions[current - 1];
                        let prev = &result.redactions[prev_idx];
                        let key = (prev.original_text.clone(), prev.label.clone());
                        self.decisions.remove(&key);
                        current -= 1;
                    }
                }
                ReviewAction::Quit => {
                    break;
                }
            }
        }

        // Apply all decisions
        for redaction in &mut result.redactions {
            let key = (redaction.original_text.clone(), redaction.label.clone());
            if let Some(&accepted) = self.decisions.get(&key) {
                redaction.accepted = accepted;
            }
        }

        Ok(())
    }

    fn display_redaction(
        &self,
        redaction: &Redaction,
        current: usize,
        total: usize,
        file_path: &std::path::Path,
    ) -> Result<()> {
        let mut stdout = io::stdout();

        execute!(stdout, terminal::Clear(ClearType::All), cursor::MoveTo(0, 0))?;

        let progress = current as f64 / total as f64;
        let bar_width = 20;
        let filled = (progress * bar_width as f64) as usize;
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_width - filled);
        
        // Use \r\n for raw mode
        write!(stdout, "[{}] {}/{} ({:.1}%)\r\n", bar, current, total, progress * 100.0)?;

        write!(stdout, "File: {}\r\n", file_path.display())?;
        write!(stdout, "Row: {} Type: {} Line: {} Col: {}\r\n", 
            redaction.row_id, 
            redaction.source,
            redaction.line,
            redaction.col
        )?;
        write!(stdout, "Source: {} Label: {}\r\n", redaction.source, redaction.label)?;

        let display_text = if redaction.original_text.len() > 60 {
            format!("{}...", &redaction.original_text[..60])
        } else {
            redaction.original_text.clone()
        };
        write!(stdout, "Context: ...{}...\r\n", display_text)?;
        
        write!(stdout, "\r\n")?;
        write!(stdout, "Accept redaction? (y/n, arrows: left=no right=yes up=redo)\r\n")?;

        stdout.flush()?;
        Ok(())
    }

    fn get_user_input(&self) -> Result<ReviewAction> {
        loop {
            if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                return Ok(match code {
                    KeyCode::Char('y') | KeyCode::Right => ReviewAction::Accept,
                    KeyCode::Char('n') | KeyCode::Left => ReviewAction::Reject,
                    KeyCode::Up => ReviewAction::Redo,
                    KeyCode::Char('q') | KeyCode::Esc => ReviewAction::Quit,
                    _ => continue,
                });
            }
        }
    }

    fn cache_decision(&mut self, redaction: &Redaction, accepted: bool) {
        let key = (redaction.original_text.clone(), redaction.label.clone());
        self.decisions.insert(key, accepted);
    }
}

impl Default for ReviewSession {
    fn default() -> Self {
        Self::new()
    }
}

enum ReviewAction {
    Accept,
    Reject,
    Redo,
    Quit,
}

/// Guard to restore terminal state on drop
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), cursor::Show);
    }
}

