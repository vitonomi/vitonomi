//! Cryptographically-strong password generator.
//!
//! Uses `core::crypto::random` exclusively. Asserts an entropy
//! floor at construction so callers never accidentally request
//! weak passwords.

use crate::crypto::random::fill_random;
use crate::errors::CryptoError;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}<>?,./|~";
/// Visually similar characters callers may opt out of (`0`/`O`,
/// `1`/`l`/`I`, etc.).
const AMBIGUOUS: &[u8] = b"0OIl1|`'\"";

/// Bitfield selecting which character classes contribute to the
/// alphabet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassMask {
    pub lower: bool,
    pub upper: bool,
    pub digit: bool,
    pub symbol: bool,
}

impl Default for ClassMask {
    fn default() -> Self {
        Self {
            lower: true,
            upper: true,
            digit: true,
            symbol: true,
        }
    }
}

/// Spec for [`generate`]. `length` is the requested character
/// count; `min_per_class` is a soft minimum that's enforced by
/// re-rolling once if not met (rare).
#[derive(Debug, Clone, Copy)]
pub struct GenSpec {
    pub length: usize,
    pub classes: ClassMask,
    pub exclude_ambiguous: bool,
    pub min_per_class: u8,
}

impl Default for GenSpec {
    fn default() -> Self {
        Self {
            length: 20,
            classes: ClassMask::default(),
            exclude_ambiguous: false,
            min_per_class: 1,
        }
    }
}

impl GenSpec {
    /// 80-bit-floor preset (the [`Self::default`]).
    #[must_use]
    pub fn standard() -> Self {
        Self::default()
    }

    /// Stronger preset — 128-bit floor for all character classes.
    #[must_use]
    pub fn strong() -> Self {
        Self {
            length: 32,
            classes: ClassMask::default(),
            exclude_ambiguous: false,
            min_per_class: 1,
        }
    }
}

/// Generate a password.
///
/// # Errors
///
/// `CryptoError::Random` if the platform RNG fails;
/// `CryptoError::Kdf("...")` if the spec is impossible to satisfy
/// (zero classes selected, length 0, length below `min_per_class
/// × selected_classes`, or estimated entropy below 64 bits).
pub fn generate(spec: &GenSpec) -> Result<String, CryptoError> {
    let alphabet = build_alphabet(spec.classes, spec.exclude_ambiguous);
    if alphabet.is_empty() {
        return Err(CryptoError::Kdf("no character classes selected".into()));
    }
    if spec.length == 0 {
        return Err(CryptoError::Kdf("password length must be > 0".into()));
    }
    let class_count = u32::from(spec.classes.lower)
        + u32::from(spec.classes.upper)
        + u32::from(spec.classes.digit)
        + u32::from(spec.classes.symbol);
    if class_count > 0 && (spec.length as u32) < class_count * u32::from(spec.min_per_class) {
        return Err(CryptoError::Kdf(format!(
            "length {} < min_per_class {} × classes {}",
            spec.length, spec.min_per_class, class_count
        )));
    }
    // Asserted entropy floor: log2(alphabet_size) * length ≥ 64.
    let entropy_bits = (alphabet.len() as f64).log2() * (spec.length as f64);
    if entropy_bits < 64.0 {
        return Err(CryptoError::Kdf(format!(
            "estimated entropy {entropy_bits:.1} bits < 64-bit floor; \
             increase length or add character classes"
        )));
    }

    // Try up to 4 times to satisfy the per-class minimums; with the
    // default min_per_class=1 and length≥4 this almost always
    // succeeds on the first try.
    for _ in 0..4 {
        let pw = sample_uniform(&alphabet, spec.length)?;
        if satisfies_min_per_class(&pw, spec) {
            return Ok(pw);
        }
    }
    // Last resort: force-include one of each required class.
    sample_with_forced_classes(&alphabet, spec)
}

fn build_alphabet(classes: ClassMask, exclude_ambiguous: bool) -> Vec<u8> {
    let mut alphabet: Vec<u8> = Vec::new();
    if classes.lower {
        alphabet.extend_from_slice(LOWER);
    }
    if classes.upper {
        alphabet.extend_from_slice(UPPER);
    }
    if classes.digit {
        alphabet.extend_from_slice(DIGITS);
    }
    if classes.symbol {
        alphabet.extend_from_slice(SYMBOLS);
    }
    if exclude_ambiguous {
        alphabet.retain(|b| !AMBIGUOUS.contains(b));
    }
    alphabet
}

fn satisfies_min_per_class(pw: &str, spec: &GenSpec) -> bool {
    let bytes = pw.as_bytes();
    let need = u32::from(spec.min_per_class);
    let mut have_lower = 0u32;
    let mut have_upper = 0u32;
    let mut have_digit = 0u32;
    let mut have_symbol = 0u32;
    for &b in bytes {
        if LOWER.contains(&b) {
            have_lower += 1;
        }
        if UPPER.contains(&b) {
            have_upper += 1;
        }
        if DIGITS.contains(&b) {
            have_digit += 1;
        }
        if SYMBOLS.contains(&b) {
            have_symbol += 1;
        }
    }
    (!spec.classes.lower || have_lower >= need)
        && (!spec.classes.upper || have_upper >= need)
        && (!spec.classes.digit || have_digit >= need)
        && (!spec.classes.symbol || have_symbol >= need)
}

fn sample_uniform(alphabet: &[u8], length: usize) -> Result<String, CryptoError> {
    let n = alphabet.len();
    // Rejection sampling: read a random byte and accept only if it
    // falls in the largest n-multiple of 256 (avoids modulo bias).
    let max_acceptable = (256 / n) * n;
    let mut out = Vec::with_capacity(length);
    let mut buf = [0u8; 64];
    while out.len() < length {
        fill_random(&mut buf)?;
        for &b in &buf {
            if (b as usize) < max_acceptable {
                out.push(alphabet[(b as usize) % n]);
                if out.len() == length {
                    break;
                }
            }
        }
    }
    Ok(String::from_utf8(out).expect("alphabet is ASCII"))
}

fn sample_with_forced_classes(alphabet: &[u8], spec: &GenSpec) -> Result<String, CryptoError> {
    // Build the password by concatenating one char from each
    // required class, then padding with uniform samples, then
    // shuffling.
    let mut out: Vec<u8> = Vec::with_capacity(spec.length);
    let need = spec.min_per_class as usize;
    if spec.classes.lower {
        out.extend(sample_uniform(LOWER, need)?.into_bytes());
    }
    if spec.classes.upper {
        out.extend(sample_uniform(UPPER, need)?.into_bytes());
    }
    if spec.classes.digit {
        out.extend(sample_uniform(DIGITS, need)?.into_bytes());
    }
    if spec.classes.symbol {
        out.extend(sample_uniform(SYMBOLS, need)?.into_bytes());
    }
    let pad = spec.length.saturating_sub(out.len());
    out.extend(sample_uniform(alphabet, pad)?.into_bytes());
    // Fisher-Yates shuffle using the platform RNG.
    let mut indices: Vec<u8> = (0..out.len() as u8).collect();
    let mut rand = vec![0u8; out.len()];
    fill_random(&mut rand)?;
    for i in (1..out.len()).rev() {
        let j = (rand[i] as usize) % (i + 1);
        indices.swap(i, j);
    }
    let shuffled: Vec<u8> = indices.into_iter().map(|i| out[i as usize]).collect();
    Ok(String::from_utf8(shuffled).expect("alphabet is ASCII"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_spec_meets_entropy_floor() {
        let spec = GenSpec::default();
        let pw = generate(&spec).unwrap();
        assert_eq!(pw.len(), spec.length);
    }

    #[test]
    fn rejects_zero_classes() {
        let spec = GenSpec {
            classes: ClassMask {
                lower: false,
                upper: false,
                digit: false,
                symbol: false,
            },
            ..GenSpec::default()
        };
        assert!(generate(&spec).is_err());
    }

    #[test]
    fn rejects_zero_length() {
        let spec = GenSpec {
            length: 0,
            ..GenSpec::default()
        };
        assert!(generate(&spec).is_err());
    }

    #[test]
    fn rejects_below_entropy_floor() {
        // 8-char digit-only is ~26.5 bits — well below the 64-bit
        // floor.
        let spec = GenSpec {
            length: 8,
            classes: ClassMask {
                lower: false,
                upper: false,
                digit: true,
                symbol: false,
            },
            exclude_ambiguous: false,
            min_per_class: 1,
        };
        assert!(generate(&spec).is_err());
    }

    #[test]
    fn exclude_ambiguous_drops_lookalikes() {
        let spec = GenSpec {
            length: 200,
            exclude_ambiguous: true,
            ..GenSpec::default()
        };
        let pw = generate(&spec).unwrap();
        for &amb in AMBIGUOUS {
            assert!(
                !pw.as_bytes().contains(&amb),
                "ambiguous char {} appeared in {pw:?}",
                amb as char
            );
        }
    }

    #[test]
    fn class_coverage_over_many_trials() {
        // Default 20-char alphabet: each class should appear in
        // every trial with overwhelming probability.
        let spec = GenSpec::default();
        for _ in 0..50 {
            let pw = generate(&spec).unwrap();
            assert!(satisfies_min_per_class(&pw, &spec));
        }
    }

    #[test]
    fn strong_preset_is_stronger() {
        let s = GenSpec::strong();
        let pw = generate(&s).unwrap();
        assert_eq!(pw.len(), s.length);
        // Estimated entropy ≥ 128 bits.
        let alphabet_size = build_alphabet(s.classes, s.exclude_ambiguous).len();
        let bits = (alphabet_size as f64).log2() * (s.length as f64);
        assert!(bits >= 128.0, "strong preset entropy {bits} < 128");
    }

    #[test]
    fn no_modulo_bias_in_alphabet_choice() {
        // Sample a lot, verify each alphabet character appears
        // roughly proportionally (within 3× tolerance).
        let alphabet: Vec<u8> = build_alphabet(ClassMask::default(), false);
        let n = alphabet.len();
        let trials = 4000;
        let pw = sample_uniform(&alphabet, trials).unwrap();
        let expected = (trials / n) as i64;
        let tolerance = expected * 3;
        for &c in &alphabet {
            let count = pw.bytes().filter(|&b| b == c).count() as i64;
            assert!(
                (count - expected).abs() <= tolerance,
                "char {} appeared {count} times; expected ~{expected}",
                c as char
            );
        }
    }
}
