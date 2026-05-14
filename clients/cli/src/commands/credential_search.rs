//! `vitonomi-cli credential search <query>` — search credentials
//! only (filtered subset of `vitonomi-cli search`).

use std::collections::HashSet;
use std::path::Path;

use vitonomi_core::record::RecordType;
use vitonomi_core::search::LibraryQuery;

use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct CredentialSearchArgs<'a> {
    pub state_path: &'a Path,
    pub query: String,
    pub limit: usize,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: CredentialSearchArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let q = LibraryQuery {
        text: args.query,
        types: Some([RecordType::Credential].into_iter().collect::<HashSet<_>>()),
        limit: args.limit,
    };
    let hits = session.index.search(&q);
    if hits.is_empty() {
        eprintln!("(no matches)");
    } else {
        for hit in hits {
            let sub = hit.subtitle.as_deref().unwrap_or("");
            println!("{}  {}  {}", hit.record_id.to_hex(), hit.title, sub);
        }
    }
    session.shutdown().await;
    Ok(())
}
