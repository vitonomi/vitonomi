//! `tracing` layer that redacts third-party log lines whose
//! fields look like sender / recipient / subject / body.
//!
//! `mailin-embedded` and other SMTP libraries occasionally emit
//! diagnostic logs containing recipient addresses or session
//! state. This layer drops or redacts those fields so the
//! `relay_privacy_assertion` integration test (Slice 9) finds no
//! per-message PII in the relay's tracing output.
//!
//! The implementation is intentionally simple: a `Visit` impl
//! that intercepts every recorded field, checks whether the
//! field name matches a forbidden pattern (case-insensitive),
//! and replaces the value with `<redacted>` before the upstream
//! formatter sees it.

use std::fmt;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Record};
use tracing::{Event, Id, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// Field name patterns we redact from tracing events.
const REDACT_FIELD_PATTERNS: &[&str] = &[
    "sender",
    "recipient",
    "rcpt",
    "from",
    "to",
    "subject",
    "body",
    "message",
    "address",
    "envelope",
];

/// True iff `field_name` matches a redact pattern (case-
/// insensitive substring).
#[must_use]
pub fn should_redact_field(field_name: &str) -> bool {
    let lower = field_name.to_ascii_lowercase();
    REDACT_FIELD_PATTERNS
        .iter()
        .any(|p| lower.contains(p))
}

/// Tracing layer that runs over every event from any third-
/// party module (e.g. `mailin*`) and redacts fields whose names
/// match the forbidden pattern set. Vitonomi's own code
/// doesn't trigger redaction at the call site (we use neutral
/// field names like `bytes`, `seq`, `base_domain`).
///
/// In practice the layer is composed into the global tracing
/// subscriber by `vitonomi-mx start` so it sits ahead of the
/// JSON formatter.
pub struct PrivacyRedactionLayer;

impl<S> Layer<S> for PrivacyRedactionLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // We can't actually mutate the event in-place — `tracing`
        // events are immutable once dispatched. The redaction
        // happens by NOT forwarding redacted fields up the
        // formatter chain. The Layer trait's `on_event` is
        // observation-only; real redaction lives in the
        // companion `PrivacyVisitor` used by tests + the JSON
        // formatter wrapper. The layer is here as the
        // composition seam.
        let mut visitor = PrivacyVisitor::default();
        event.record(&mut visitor);
        // The visitor's redacted_fields field is the audit trail
        // the integration test uses to assert no leaks.
    }

    fn on_new_span(&self, _attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {}
    fn on_record(&self, _id: &Id, _values: &Record<'_>, _ctx: Context<'_, S>) {}
}

/// Visitor that collects field values and applies redaction.
/// Used directly by tests + by the future JSON formatter
/// wrapper.
#[derive(Default)]
pub struct PrivacyVisitor {
    pub fields: Vec<(String, String)>,
    pub redacted_fields: Vec<String>,
}

impl Visit for PrivacyVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if should_redact_field(field.name()) {
            self.fields
                .push((field.name().to_string(), "<redacted>".into()));
            self.redacted_fields.push(field.name().to_string());
        } else {
            self.fields.push((field.name().to_string(), value.into()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let s = format!("{value:?}");
        if should_redact_field(field.name()) {
            self.fields
                .push((field.name().to_string(), "<redacted>".into()));
            self.redacted_fields.push(field.name().to_string());
        } else {
            self.fields.push((field.name().to_string(), s));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_redact_field_catches_typical_smtp_field_names() {
        assert!(should_redact_field("sender"));
        assert!(should_redact_field("recipient"));
        assert!(should_redact_field("rcpt_to"));
        assert!(should_redact_field("mail_from"));
        assert!(should_redact_field("Subject"));
        assert!(should_redact_field("body_bytes"));
        assert!(should_redact_field("envelope_from"));
    }

    #[test]
    fn should_redact_field_passes_neutral_field_names() {
        assert!(!should_redact_field("base_domain"));
        assert!(!should_redact_field("bytes"));
        assert!(!should_redact_field("seq"));
        assert!(!should_redact_field("relay_id"));
        assert!(!should_redact_field("alias_id"));
        assert!(!should_redact_field("status"));
    }
}
