//! Cross-platform clipboard write with auto-clear.
//!
//! On a host with no clipboard (CI, headless server, SSH session
//! without DISPLAY), `arboard::Clipboard::new()` errors at
//! construct time and we surface that to the caller via
//! [`CopyOutcome::HeadlessFallback`] — the caller is expected to
//! print the secret to stdout instead.
//!
//! When clipboard is available, the secret is set, the function
//! sleeps for `ttl`, and then the clipboard is cleared (best
//! effort — another app may have taken ownership in the
//! meantime).

use std::time::Duration;

use vitonomi_core::types::credential::SecretString;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOutcome {
    /// Secret was placed on the clipboard; will auto-clear after
    /// `ttl`.
    Copied,
    /// No clipboard available (headless host). Caller should
    /// print the secret to stdout instead.
    HeadlessFallback,
}

/// Place `text` on the clipboard, sleep `ttl`, clear. Spawns a
/// task for the sleep + clear so the CLI doesn't block the
/// foreground.
///
/// Returns immediately after the initial set with
/// `CopyOutcome::Copied`. `HeadlessFallback` is returned if
/// `arboard::Clipboard::new()` fails (no display server).
///
/// # Errors
///
/// Returns `Err` if the clipboard is available but the set
/// itself fails (rare; e.g. selection denied).
pub fn copy_with_autoclear(text: SecretString, ttl: Duration) -> Result<CopyOutcome, String> {
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(_) => return Ok(CopyOutcome::HeadlessFallback),
    };
    clipboard
        .set_text(text.expose_secret().to_string())
        .map_err(|e| format!("clipboard set: {e}"))?;
    let cleared_text = String::new();
    tokio::spawn(async move {
        tokio::time::sleep(ttl).await;
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            // Best-effort clear; another app may own the clipboard
            // by now.
            let _ = clipboard.set_text(cleared_text);
        }
    });
    Ok(CopyOutcome::Copied)
}
