//! Password / username / confirmation prompts. Hidden behind a
//! trait so integration tests can inject scripted answers.

use anyhow::{anyhow, Result};

pub trait Prompts: Send + Sync {
    /// Read a username (visible echo).
    fn username(&mut self, prompt: &str) -> Result<String>;
    /// Read a password (no echo). If `confirm` is true, ask twice
    /// and reject mismatches.
    fn password(&mut self, prompt: &str, confirm: bool) -> Result<String>;
    /// Read a multi-word seed phrase (no echo).
    fn seed_phrase(&mut self, prompt: &str) -> Result<String>;
}

/// Real-stdin prompts using `dialoguer`.
pub struct InteractivePrompts;

impl Prompts for InteractivePrompts {
    fn username(&mut self, prompt: &str) -> Result<String> {
        let s: String = dialoguer::Input::new()
            .with_prompt(prompt)
            .interact_text()
            .map_err(|e| anyhow!("read username: {e}"))?;
        Ok(s.trim().to_string())
    }

    fn password(&mut self, prompt: &str, confirm: bool) -> Result<String> {
        let mut p = dialoguer::Password::new();
        p = p.with_prompt(prompt);
        if confirm {
            p = p.with_confirmation("Confirm password", "passwords don't match");
        }
        let s = p.interact().map_err(|e| anyhow!("read password: {e}"))?;
        Ok(s)
    }

    fn seed_phrase(&mut self, prompt: &str) -> Result<String> {
        let s = dialoguer::Password::new()
            .with_prompt(prompt)
            .interact()
            .map_err(|e| anyhow!("read seed phrase: {e}"))?;
        Ok(s.trim().to_string())
    }
}

/// Scripted prompts — for tests.
pub struct ScriptedPrompts {
    pub username: String,
    pub password: String,
    pub seed_phrase: String,
}

impl Prompts for ScriptedPrompts {
    fn username(&mut self, _prompt: &str) -> Result<String> {
        Ok(self.username.clone())
    }
    fn password(&mut self, _prompt: &str, _confirm: bool) -> Result<String> {
        Ok(self.password.clone())
    }
    fn seed_phrase(&mut self, _prompt: &str) -> Result<String> {
        Ok(self.seed_phrase.clone())
    }
}
