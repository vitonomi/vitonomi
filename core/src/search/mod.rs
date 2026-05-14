//! Cross-RecordType search index.
//!
//! Powers `vitonomi-cli search ...` and the PWA's universal
//! search bar. Built **only** from each RecordType's metadata
//! face (via [`RecordStore::list_metadata`]) — body chunks are
//! never fetched. Generic over RecordType: per-type schemas
//! implement [`Indexable`]; a centralised `match` in
//! [`registry::index_metadata`] dispatches on
//! [`RecordType`] and decodes via the per-type implementation.
//!
//! In Phase 6 the index is in-memory and rebuilt on each session
//! via [`LibraryIndex::populate`]; persistence to encrypted local
//! storage lands in Phase 8.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use unicode_normalization::UnicodeNormalization;

use crate::errors::{CoreError, ProtocolError};
use crate::record::record_store::{ChunkTransport, HeadPointerTransport, RecordStore};
use crate::record::{RecordId, RecordType};

pub mod registry;

/// One-record search result. Returned by [`LibraryIndex::search`].
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub record_id: RecordId,
    pub record_type: RecordType,
    pub title: String,
    pub subtitle: Option<String>,
    pub score: f32,
}

/// Inputs to a search query. `types = None` is a **universal**
/// query (all loaded RecordTypes); `types = Some(...)` restricts
/// to the listed types and short-circuits per-type postings.
#[derive(Debug, Clone)]
pub struct LibraryQuery {
    pub text: String,
    pub types: Option<HashSet<RecordType>>,
    pub limit: usize,
}

/// Per-RecordType contract for participating in the search index.
///
/// Implementors live in `core::types::*` (e.g.
/// [`crate::types::credential::CredentialMetadata`]). The closed
/// `RecordType` enum makes this dispatch a compile-time-checked
/// `match` in [`registry`] — new RecordTypes add one match arm.
pub trait Indexable: Sized {
    /// The RecordType this implementation indexes.
    const RECORD_TYPE: RecordType;

    /// Decode the raw metadata bytes (as produced by the per-type
    /// `to_metadata_bytes`) into `Self`.
    ///
    /// # Errors
    ///
    /// Bubble up the type's own decode error as `ProtocolError`.
    fn from_metadata_bytes(bytes: &[u8]) -> Result<Self, ProtocolError>;

    /// Free-text tokens this record contributes to the inverted
    /// index. Caller normalises (NFC + lowercase + de-dup); this
    /// implementation just yields the source strings.
    fn tokens(&self) -> Vec<Cow<'_, str>>;

    /// `(key, value)` filter pairs (folder, tag, …). Stored
    /// alongside the doc; not used by the simple Phase 6 search but
    /// available to UI layers and to future facet queries.
    fn filter_keys(&self) -> Vec<(&'static str, Cow<'_, str>)>;

    /// Build the [`SearchHit`] returned for this doc when it
    /// matches a query (without the `score` field, which is set
    /// by the index at query time).
    fn build_hit(&self, record_id: RecordId) -> SearchHit;
}

/// Decoded view of one indexed document. Produced by
/// [`registry::index_metadata`].
pub struct IndexedDoc {
    pub tokens: Vec<String>,
    pub filter_keys: Vec<(String, String)>,
    pub hit: SearchHit,
}

/// In-memory cross-type search index.
///
/// Backing storage: per-RecordType `TypePostings`. Each holds a
/// monotonic `docs` vector (slot index = doc id), a `by_id` map
/// from `RecordId` to slot, and an inverted `postings` map
/// `token → Vec<slot index>`. Removed records leave a tombstone
/// slot (cheap; not collected).
///
/// Scoring: term frequency only (no IDF). Sufficient for the
/// 5 000-credential P95 ≤ 50 ms target.
#[derive(Default)]
pub struct LibraryIndex {
    per_type: HashMap<RecordType, TypePostings>,
}

#[derive(Default)]
struct TypePostings {
    by_id: HashMap<RecordId, usize>,
    docs: Vec<Option<DocSlot>>,
    postings: HashMap<String, Vec<usize>>,
}

struct DocSlot {
    hit: SearchHit,
    /// Tokens originally indexed for this doc. Kept so a future
    /// upsert / remove can update postings precisely.
    tokens: Vec<String>,
}

impl LibraryIndex {
    /// Empty index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            per_type: HashMap::new(),
        }
    }

    /// Build an index by `list_metadata`-ing every type in
    /// `types`, decoding each metadata blob, and inserting the
    /// resulting tokens. Body chunks are never fetched — all
    /// `RecordStore::list_metadata` does is read snapshot frames
    /// and the per-record metadata blobs.
    ///
    /// # Errors
    ///
    /// Any underlying transport / crypto / decode failure.
    pub async fn populate<C: ChunkTransport, H: HeadPointerTransport>(
        store: &RecordStore<C, H>,
        types: &[RecordType],
    ) -> Result<Self, CoreError> {
        let mut idx = Self::new();
        for &rt in types {
            let listed = store.list_metadata(rt).await?;
            for (id, bytes) in listed {
                idx.upsert(rt, id, &bytes).map_err(CoreError::Protocol)?;
            }
        }
        Ok(idx)
    }

    /// Insert or replace a record's index entry. If the record was
    /// already indexed under `(rt, id)`, its prior tokens are
    /// removed from postings before the new ones are added.
    ///
    /// # Errors
    ///
    /// `ProtocolError` from the per-type metadata decode (e.g.
    /// malformed CBOR, unknown variant).
    pub fn upsert(
        &mut self,
        rt: RecordType,
        record_id: RecordId,
        metadata_bytes: &[u8],
    ) -> Result<(), ProtocolError> {
        let doc = registry::index_metadata(rt, record_id, metadata_bytes)?;

        let postings = self.per_type.entry(rt).or_default();

        // Remove the existing entry (if any) before inserting the
        // new one.
        if let Some(prev_idx) = postings.by_id.get(&record_id).copied() {
            if let Some(Some(prev_slot)) = postings.docs.get(prev_idx) {
                let prev_tokens = prev_slot.tokens.clone();
                for tok in &prev_tokens {
                    if let Some(list) = postings.postings.get_mut(tok) {
                        list.retain(|&i| i != prev_idx);
                        if list.is_empty() {
                            postings.postings.remove(tok);
                        }
                    }
                }
            }
            postings.docs[prev_idx] = None;
            postings.by_id.remove(&record_id);
        }

        let normalized: Vec<String> = doc
            .tokens
            .iter()
            .flat_map(|t| tokenize(t))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let slot = DocSlot {
            hit: doc.hit,
            tokens: normalized.clone(),
        };
        // Reuse the first tombstoned slot if any, else push.
        let new_idx = match postings.docs.iter().position(|s| s.is_none()) {
            Some(i) => {
                postings.docs[i] = Some(slot);
                i
            }
            None => {
                postings.docs.push(Some(slot));
                postings.docs.len() - 1
            }
        };
        postings.by_id.insert(record_id, new_idx);
        for tok in normalized {
            postings.postings.entry(tok).or_default().push(new_idx);
        }
        let _ = doc.filter_keys; // reserved for facet queries (Phase 8+)
        Ok(())
    }

    /// Remove a record from the index. No-op if absent.
    pub fn remove(&mut self, rt: RecordType, record_id: RecordId) {
        let Some(postings) = self.per_type.get_mut(&rt) else {
            return;
        };
        let Some(idx) = postings.by_id.remove(&record_id) else {
            return;
        };
        if let Some(Some(slot)) = postings.docs.get(idx) {
            let tokens = slot.tokens.clone();
            for tok in &tokens {
                if let Some(list) = postings.postings.get_mut(tok) {
                    list.retain(|&i| i != idx);
                    if list.is_empty() {
                        postings.postings.remove(tok);
                    }
                }
            }
        }
        if let Some(slot) = postings.docs.get_mut(idx) {
            *slot = None;
        }
    }

    /// Run `q`, returning up to `q.limit` hits sorted by score
    /// descending. Empty query text returns an empty result set
    /// (Phase 6 doesn't have a "browse all" mode at this layer —
    /// callers use `RecordStore::list_metadata` directly for
    /// that).
    #[must_use]
    pub fn search(&self, q: &LibraryQuery) -> Vec<SearchHit> {
        let query_tokens: Vec<String> = tokenize(&q.text);
        if query_tokens.is_empty() {
            return Vec::new();
        }
        // Score per (rt, doc-slot) — accumulate term frequency.
        let mut scores: HashMap<(RecordType, usize), f32> = HashMap::new();
        for (&rt, postings) in &self.per_type {
            if let Some(types) = q.types.as_ref() {
                if !types.contains(&rt) {
                    continue;
                }
            }
            for tok in &query_tokens {
                if let Some(idxs) = postings.postings.get(tok) {
                    for &idx in idxs {
                        *scores.entry((rt, idx)).or_insert(0.0) += 1.0;
                    }
                }
            }
        }
        let mut hits: Vec<SearchHit> = scores
            .into_iter()
            .filter_map(|((rt, idx), score)| {
                let postings = self.per_type.get(&rt)?;
                let slot = postings.docs.get(idx)?.as_ref()?;
                let mut hit = slot.hit.clone();
                hit.score = score;
                Some(hit)
            })
            .collect();
        // Stable sort: score descending, then title for ties.
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.title.cmp(&b.title))
        });
        hits.truncate(q.limit);
        hits
    }

    /// Number of live (non-tombstoned) docs across all loaded
    /// RecordTypes.
    #[must_use]
    pub fn live_doc_count(&self) -> usize {
        self.per_type
            .values()
            .map(|p| p.docs.iter().filter(|s| s.is_some()).count())
            .sum()
    }
}

/// Tokenise a free-text source string into the searchable token
/// stream stored in postings: NFC-normalise → ASCII-lowercase →
/// split on non-alphanumerics → drop empties.
fn tokenize(text: &str) -> Vec<String> {
    let normalized: String = text.nfc().collect();
    let lowered = normalized.to_ascii_lowercase();
    lowered
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Best-effort URL host extractor used by per-type `Indexable`
/// implementations. Returns `None` for empty / scheme-only URLs.
#[must_use]
pub fn url_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.split('@').next_back().unwrap_or(host); // strip user:pass@
    let host = host.split(':').next().unwrap_or(host); // strip :port
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::credential::CredentialMetadata;
    use crate::types::FormatVersion;

    fn cm(title: &str, url: Option<&str>, tags: &[&str], folder: Option<&str>) -> CredentialMetadata {
        CredentialMetadata {
            format_version: FormatVersion::V1,
            title: title.into(),
            url: url.map(str::to_string),
            username: None,
            tags: tags.iter().map(|s| s.to_string()).collect(),
            folder: folder.map(str::to_string),
            has_totp: false,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }

    fn add(idx: &mut LibraryIndex, id_byte: u8, m: &CredentialMetadata) -> RecordId {
        let id = RecordId([id_byte; 16]);
        let bytes = m.to_metadata_bytes().unwrap();
        idx.upsert(RecordType::Credential, id, &bytes).unwrap();
        id
    }

    fn q(text: &str, types: Option<HashSet<RecordType>>) -> LibraryQuery {
        LibraryQuery {
            text: text.into(),
            types,
            limit: 50,
        }
    }

    #[test]
    fn tokenize_lowercases_and_splits_on_non_alphanumerics() {
        assert_eq!(
            tokenize("Hello, World! v2.0"),
            vec!["hello", "world", "v2", "0"]
        );
        assert_eq!(
            tokenize("  multiple   spaces  "),
            vec!["multiple", "spaces"]
        );
    }

    #[test]
    fn tokenize_nfc_normalises_unicode() {
        // Composed (é = U+00E9) vs decomposed (e + U+0301) compose
        // to the same NFC byte sequence.
        let composed = "café";
        let decomposed = "cafe\u{0301}";
        assert_eq!(tokenize(composed), tokenize(decomposed));
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(url_host("https://github.com/user/repo"), Some("github.com".into()));
        assert_eq!(url_host("http://example.org:8080/x"), Some("example.org".into()));
        assert_eq!(url_host("user:pw@host.example.com/path"), Some("host.example.com".into()));
        assert_eq!(url_host(""), None);
    }

    #[test]
    fn search_finds_by_title_token() {
        let mut idx = LibraryIndex::new();
        let g = add(&mut idx, 1, &cm("GitHub", Some("https://github.com"), &[], None));
        let n = add(&mut idx, 2, &cm("Netflix", Some("https://netflix.com"), &[], None));
        let hits = idx.search(&q("github", None));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, g);
        let _ = n;
    }

    #[test]
    fn search_finds_by_url_host_token() {
        let mut idx = LibraryIndex::new();
        let g = add(&mut idx, 1, &cm("Code Host", Some("https://github.com"), &[], None));
        let _ = add(&mut idx, 2, &cm("Movie Host", Some("https://netflix.com"), &[], None));
        let hits = idx.search(&q("github", None));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, g);
    }

    #[test]
    fn search_finds_by_tag_token() {
        let mut idx = LibraryIndex::new();
        let _ = add(&mut idx, 1, &cm("Foo", None, &["work"], None));
        let p = add(&mut idx, 2, &cm("Bar", None, &["personal"], None));
        let hits = idx.search(&q("personal", None));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, p);
    }

    #[test]
    fn search_finds_by_folder_token() {
        let mut idx = LibraryIndex::new();
        let _ = add(&mut idx, 1, &cm("X", None, &[], Some("home")));
        let w = add(&mut idx, 2, &cm("Y", None, &[], Some("work")));
        let hits = idx.search(&q("work", None));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, w);
    }

    #[test]
    fn empty_query_returns_empty_results() {
        let mut idx = LibraryIndex::new();
        let _ = add(&mut idx, 1, &cm("X", None, &[], None));
        assert!(idx.search(&q("", None)).is_empty());
    }

    #[test]
    fn filtered_query_skips_other_record_types() {
        // Phase 6 only wires Credential indexing; constructing the
        // filter HashSet with just Credential is the universal
        // case here. We additionally test that an explicit filter
        // for {Alias} (a type with no docs) returns zero hits even
        // when credentials match.
        let mut idx = LibraryIndex::new();
        let _ = add(&mut idx, 1, &cm("GitHub", None, &[], None));
        let only_alias: HashSet<RecordType> = [RecordType::Alias].into_iter().collect();
        assert!(idx.search(&q("github", Some(only_alias))).is_empty());
        let only_cred: HashSet<RecordType> = [RecordType::Credential].into_iter().collect();
        assert_eq!(idx.search(&q("github", Some(only_cred))).len(), 1);
    }

    #[test]
    fn upsert_replaces_prior_tokens() {
        let mut idx = LibraryIndex::new();
        let id = add(&mut idx, 1, &cm("OldTitle", None, &[], None));
        // Re-upsert with a different title — old token should be
        // gone, new token findable.
        let m = cm("NewTitle", None, &[], None);
        let bytes = m.to_metadata_bytes().unwrap();
        idx.upsert(RecordType::Credential, id, &bytes).unwrap();
        assert!(idx.search(&q("oldtitle", None)).is_empty());
        let hits = idx.search(&q("newtitle", None));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id, id);
    }

    #[test]
    fn remove_purges_record() {
        let mut idx = LibraryIndex::new();
        let id = add(&mut idx, 1, &cm("ToBeRemoved", None, &[], None));
        assert_eq!(idx.search(&q("toberemoved", None)).len(), 1);
        idx.remove(RecordType::Credential, id);
        assert!(idx.search(&q("toberemoved", None)).is_empty());
        // No-op on second remove.
        idx.remove(RecordType::Credential, id);
        assert!(idx.search(&q("toberemoved", None)).is_empty());
    }

    #[test]
    fn ranking_by_term_frequency() {
        // Two-token query ("github" + "personal"); doc that
        // matches both should score higher than a doc that
        // matches one.
        let mut idx = LibraryIndex::new();
        let both = add(
            &mut idx,
            1,
            &cm("GitHub Personal", None, &[], None),
        );
        let one = add(&mut idx, 2, &cm("GitHub Work", None, &[], None));
        let hits = idx.search(&q("github personal", None));
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].record_id, both);
        assert_eq!(hits[1].record_id, one);
        assert!(hits[0].score > hits[1].score);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn populate_against_record_store_only_uses_list_metadata() {
        // Wire a real RecordStore against the in-memory transports
        // and assert populate calls list_metadata (zero body
        // fetches). We re-use the in-memory transport from
        // record_store::tests by building locally — keeping core
        // unit tests free of cross-module dependencies.

        use crate::crypto::pq::ml_dsa_65_keypair;
        use crate::crypto::seedphrase::SeedPhrase;
        use crate::record::record_store::{
            BodyOp, ChunkTransport, HeadPointerTransport, RecordPlaintext, RecordStore, UserKeys,
        };
        use crate::record::user_keys::derive_user_aead_master;
        use crate::types::{ClusterId, UserId};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        // ── tiny in-memory transports + a counting decorator ──
        struct Mem {
            inner: Arc<Mutex<HashMap<[u8; 32], Vec<u8>>>>,
            gets: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl ChunkTransport for Mem {
            async fn put_chunks(
                &self,
                chunks: &[crate::crypto::selfencrypt::Chunk],
            ) -> Result<(), CoreError> {
                let mut g = self.inner.lock().unwrap();
                for c in chunks {
                    g.insert(c.address.0, c.bytes.clone());
                }
                Ok(())
            }
            async fn get_chunk(
                &self,
                address: &crate::protocol::autonomi_bridge::ChunkAddress,
            ) -> Result<Vec<u8>, CoreError> {
                self.gets.fetch_add(1, Ordering::SeqCst);
                let g = self.inner.lock().unwrap();
                g.get(&address.0).cloned().ok_or(CoreError::Storage(
                    crate::errors::StorageError::NotFound,
                ))
            }
        }
        struct HeadStore {
            inner: Arc<Mutex<HashMap<u8, crate::record::head_pointer::StoredHeadPointer>>>,
        }
        #[async_trait::async_trait]
        impl HeadPointerTransport for HeadStore {
            async fn get(
                &self,
                rt: RecordType,
            ) -> Result<Option<crate::record::head_pointer::StoredHeadPointer>, CoreError>
            {
                Ok(self.inner.lock().unwrap().get(&rt.as_u8()).cloned())
            }
            async fn put(
                &self,
                rt: RecordType,
                stored: crate::record::head_pointer::StoredHeadPointer,
            ) -> Result<(), CoreError> {
                self.inner.lock().unwrap().insert(rt.as_u8(), stored);
                Ok(())
            }
        }

        // ── build store ──
        let kp = ml_dsa_65_keypair().unwrap();
        let phrase = SeedPhrase::generate().unwrap();
        let seed = phrase.to_seed("");
        let master = derive_user_aead_master(&seed);
        let keys = UserKeys {
            user_id: UserId([42u8; 16]),
            cluster_id: ClusterId([7u8; 32]),
            identity_pk: kp.public,
            identity_sk: kp.secret,
            user_aead_master: master,
        };
        let chunks_inner = Arc::new(Mutex::new(HashMap::new()));
        let gets = Arc::new(AtomicUsize::new(0));
        let mem = Mem {
            inner: chunks_inner,
            gets: gets.clone(),
        };
        let heads = HeadStore {
            inner: Arc::new(Mutex::new(HashMap::new())),
        };
        let store = RecordStore::new(keys, mem, heads);

        // Add a few credentials with bodies; populate must skip
        // body chunk fetches.
        for i in 0..5 {
            let m = cm(&format!("Title{i}"), None, &[], None);
            let mb = m.to_metadata_bytes().unwrap();
            store
                .put(
                    RecordType::Credential,
                    RecordPlaintext {
                        metadata: mb,
                        body: BodyOp::Set(format!("body-{i}").into_bytes()),
                    },
                )
                .await
                .unwrap();
        }

        let put_gets = gets.load(Ordering::SeqCst);

        let idx = LibraryIndex::populate(&store, &[RecordType::Credential])
            .await
            .unwrap();
        assert_eq!(idx.live_doc_count(), 5);

        let after_populate = gets.load(Ordering::SeqCst);
        let populate_gets = after_populate - put_gets;
        // Populate fetches only snapshot chunks (and zero body
        // chunks). With all-inline metadata + 5 records, the
        // snapshot fits in a small number of chunks (≤ a handful).
        // Body fetches would be ≥ 5; assert strictly less.
        assert!(
            populate_gets < 5,
            "populate fetched {populate_gets} chunks; expected < 5 \
             (snapshot only, no body chunks)"
        );

        // And queries against the populated index work.
        let hits = idx.search(&q("title3", None));
        assert_eq!(hits.len(), 1);
    }
}
