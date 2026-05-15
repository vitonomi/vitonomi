//! `vitonomi-cli alias search <query>` — search across `Alias` +
//! `AliasMessage` records via the cross-type `LibraryIndex`.

use std::path::Path;

use std::collections::HashSet;

use vitonomi_core::record::RecordType;
use vitonomi_core::search::LibraryQuery;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct AliasSearchArgs<'a> {
    pub state_path: &'a Path,
    pub query: String,
    pub limit: usize,
}

/// Run.
///
/// # Errors
///
/// Crypto / network / state failures.
#[allow(clippy::print_stdout)]
pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: AliasSearchArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let mut types = HashSet::new();
    types.insert(RecordType::Alias);
    types.insert(RecordType::AliasMessage);
    let q = LibraryQuery {
        text: args.query,
        types: Some(types),
        limit: args.limit,
    };
    for hit in session.index.search(&q) {
        println!(
            "{:?}\t{}\t{}",
            hit.record_type,
            hit.record_id.to_hex(),
            hit.title
        );
    }
    session.shutdown().await;
    Ok(())
}
