//! Output redaction for agent commands: removes injected secret values from
//! what a command printed before the agent sees it.
//!
//! Each value is removed as is and in common encodings (Base64 standard and
//! URL-safe, with and without padding; hex in both cases; percent-encoded).
//! This catches accidents and simple exfiltration through the output. It
//! cannot catch every transformation a command can apply (a reversed,
//! compressed or partially printed value passes), which is why commands
//! need an approval or an allowlist in the first place.

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};

/// Shorter values are not redacted: they would match ordinary output.
pub const MIN_LEN: usize = 4;

/// Replaces secrets in command output.
#[derive(Default)]
pub struct Redactor {
    /// Patterns and the label they are replaced with, longest first.
    patterns: Vec<(String, String)>,
}

fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a secret. `label` names it in the output, for example the
    /// environment variable.
    pub fn add(&mut self, value: &str, label: &str) {
        let replacement = format!("[redacted {label}]");
        let mut forms = Vec::new();
        let mut push_forms = |v: &str| {
            if v.len() < MIN_LEN {
                return;
            }
            let bytes = v.as_bytes();
            forms.extend([
                v.to_owned(),
                BASE64.encode(bytes),
                BASE64_NOPAD.encode(bytes),
                BASE64URL.encode(bytes),
                BASE64URL_NOPAD.encode(bytes),
                HEXLOWER.encode(bytes),
                HEXUPPER.encode(bytes),
                percent_encode(v),
            ]);
        };
        push_forms(value);
        // Lines of multi-line secrets (keys, certificates) on their own.
        if value.contains('\n') {
            for line in value.lines().map(str::trim).filter(|l| l.len() >= 8) {
                push_forms(line);
            }
        }
        for form in forms {
            if !self.patterns.iter().any(|(p, _)| *p == form) {
                self.patterns.push((form, replacement.clone()));
            }
        }
        self.patterns.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Returns `text` with every known secret replaced, and how many
    /// replacements were made.
    pub fn redact(&self, text: &str) -> (String, usize) {
        let mut out = text.to_owned();
        let mut count = 0;
        for (pattern, replacement) in &self.patterns {
            let found = out.matches(pattern.as_str()).count();
            if found > 0 {
                count += found;
                out = out.replace(pattern.as_str(), replacement);
            }
        }
        (out, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_values_and_encodings() {
        let mut r = Redactor::new();
        r.add("s3cr3t/token+x", "API_TOKEN");
        let text = format!(
            "plain s3cr3t/token+x b64 {} url {} hex {} pct {}",
            BASE64.encode(b"s3cr3t/token+x"),
            BASE64URL_NOPAD.encode(b"s3cr3t/token+x"),
            HEXLOWER.encode(b"s3cr3t/token+x"),
            percent_encode("s3cr3t/token+x"),
        );
        let (out, count) = r.redact(&text);
        assert!(count >= 5, "{count}");
        assert!(!out.contains("s3cr3t"), "{out}");
        assert!(out.contains("[redacted API_TOKEN]"));
    }

    #[test]
    fn ignores_short_values_and_handles_lines() {
        let mut r = Redactor::new();
        r.add("abc", "SHORT");
        assert!(r.is_empty());
        r.add("-----BEGIN KEY-----\nAAAABBBBCCCCDDDD\n-----END KEY-----", "KEY");
        let (out, _) = r.redact("leaked AAAABBBBCCCCDDDD here");
        assert_eq!(out, "leaked [redacted KEY] here");
    }
}
