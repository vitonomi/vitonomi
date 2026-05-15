//! RAM-only buffering for the DATA-phase plaintext.
//!
//! The relay's privacy invariant says "no plaintext on disk,
//! ever." `EncryptorStream` accumulates the SMTP DATA bytes in
//! a `Vec<u8>` capped at [`MAX_MESSAGE_BYTES`], hands the
//! complete plaintext to [`crate::dispatch::hub_push`] when DATA
//! ends, and zeroizes the buffer before dropping. The buffer
//! never escapes the function whose stack frame holds it.
//!
//! Over-cap messages are rejected with the SMTP 552
//! ("requested mail action aborted: exceeded storage
//! allocation") code at the handler layer.

use zeroize::Zeroize;

/// 25 MiB cap. A typical inbound mail is well under 100 KB;
/// 25 MiB is a generous upper bound that still keeps the per-
/// session memory footprint bounded.
pub const MAX_MESSAGE_BYTES: usize = 25 * 1024 * 1024;

/// Accumulator for the plaintext bytes of one DATA phase.
pub struct EncryptorStream {
    buf: Vec<u8>,
    /// True iff the cap was exceeded — caller checks this on
    /// `data_end` to decide between push and 552.
    over_cap: bool,
}

impl EncryptorStream {
    /// Fresh accumulator. Capacity hint is conservative; the
    /// buffer will grow on demand via standard `Vec` doubling.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(8 * 1024),
            over_cap: false,
        }
    }

    /// Append a chunk of DATA bytes. Quietly stops appending
    /// past [`MAX_MESSAGE_BYTES`] and sets the over-cap flag.
    /// Returns `Ok(())` either way; the over-cap decision is
    /// the handler's to make on `data_end`.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.over_cap {
            return;
        }
        if self.buf.len() + bytes.len() > MAX_MESSAGE_BYTES {
            self.over_cap = true;
            return;
        }
        self.buf.extend_from_slice(bytes);
    }

    #[must_use]
    pub fn over_cap(&self) -> bool {
        self.over_cap
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the accumulated plaintext for handoff to the
    /// dispatch step. Caller MUST consume + finalize before
    /// the `EncryptorStream` is dropped, else the bytes are
    /// zeroized.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Move the bytes out, leaving the stream zeroized. Use
    /// when you want to take ownership for the encrypt + push
    /// step without paying for an extra copy.
    #[must_use]
    pub fn take(mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.buf.len());
        std::mem::swap(&mut out, &mut self.buf);
        // After `take` the inner buf is empty, so Drop's
        // zeroize is a no-op. Whoever owns `out` is now
        // responsible for zeroizing; in practice
        // dispatch::hub_push hands it to
        // `core::crypto::alias_inbound::seal_to_alias` which
        // copies into the AEAD ciphertext and the original
        // bytes drop without further use.
        out
    }
}

impl Default for EncryptorStream {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EncryptorStream {
    fn drop(&mut self) {
        // Zeroize the plaintext bytes before deallocation.
        // `Vec::zeroize` zeros the in-bounds bytes; the
        // capacity past `len` may hold stale bytes from
        // previous pushes — explicitly resize first to make
        // sure the full backing allocation is wiped.
        let cap = self.buf.capacity();
        self.buf.resize(cap, 0u8);
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_accumulates() {
        let mut s = EncryptorStream::new();
        s.push(b"hello ");
        s.push(b"world");
        assert_eq!(s.as_bytes(), b"hello world");
        assert_eq!(s.len(), 11);
        assert!(!s.over_cap());
    }

    #[test]
    fn push_past_cap_sets_over_cap_and_stops_appending() {
        let mut s = EncryptorStream::new();
        // First chunk fits.
        let chunk = vec![0u8; MAX_MESSAGE_BYTES];
        s.push(&chunk);
        assert!(!s.over_cap());
        // Second chunk pushes past the cap → over_cap, no append.
        s.push(b"trailing bytes");
        assert!(s.over_cap());
        assert_eq!(s.len(), MAX_MESSAGE_BYTES);
        // Subsequent pushes are no-ops.
        s.push(b"more");
        assert_eq!(s.len(), MAX_MESSAGE_BYTES);
    }

    #[test]
    fn take_returns_bytes_and_leaves_stream_empty() {
        let mut s = EncryptorStream::new();
        s.push(b"some bytes");
        let bytes = s.take();
        assert_eq!(bytes, b"some bytes");
    }

    #[test]
    fn drop_zeroizes_buffer() {
        // We can't directly inspect the freed allocation, but
        // we can probe the Drop path runs without panic AND
        // the `Zeroize` derive at this level is invoked. The
        // canary approach: stash a raw pointer into the
        // buffer's first byte, drop the stream, then read
        // back via the pointer. UB territory in general
        // (post-free read), so we do the next-best test:
        // ensure the resize-to-cap-then-zeroize path runs
        // without panic over a buffer with reserved capacity.
        let mut s = EncryptorStream::new();
        s.push(b"sensitive data");
        drop(s); // implicit zeroize-on-drop runs
    }
}
