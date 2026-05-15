//! `vitonomi-cli search <query> [--type ...] [--limit N]` —
//! cross-RecordType universal search.

use std::collections::HashSet;
use std::path::Path;

use vitonomi_core::record::RecordType;
use vitonomi_core::search::LibraryQuery;

use crate::cli::RecordTypeArg;
use crate::commands::library_session;
use crate::config::CliConfig;
use crate::prompts::Prompts;

pub struct SearchArgs<'a> {
    pub state_path: &'a Path,
    pub query: String,
    pub type_filter: Option<Vec<RecordTypeArg>>,
    pub limit: usize,
}

pub async fn run<P: Prompts + ?Sized>(
    cfg: &CliConfig,
    args: SearchArgs<'_>,
    prompts: &mut P,
) -> anyhow::Result<()> {
    let session = library_session::open(cfg, args.state_path, prompts).await?;
    let types = args.type_filter.map(|v| {
        v.into_iter()
            .map(record_type_arg_to_core)
            .collect::<HashSet<RecordType>>()
    });
    let q = LibraryQuery {
        text: args.query,
        types,
        limit: args.limit,
    };
    let hits = session.index.search(&q);
    if hits.is_empty() {
        eprintln!("(no matches)");
    } else {
        for hit in hits {
            let sub = hit.subtitle.as_deref().unwrap_or("");
            println!(
                "{:?}  {}  {}  {}",
                hit.record_type,
                hit.record_id.to_hex(),
                hit.title,
                sub,
            );
        }
    }
    session.shutdown().await;
    Ok(())
}

fn record_type_arg_to_core(arg: RecordTypeArg) -> RecordType {
    match arg {
        RecordTypeArg::Credential => RecordType::Credential,
        RecordTypeArg::Alias => RecordType::Alias,
        RecordTypeArg::AliasMessage => RecordType::AliasMessage,
        RecordTypeArg::Domain => RecordType::Domain,
    }
}
