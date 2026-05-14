//! clap dispatcher for `vitonomi-cli`.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands;
use crate::config::CliConfig;
use crate::prompts::InteractivePrompts;
use crate::state;

#[derive(Debug, Parser)]
#[command(name = "vitonomi-cli", version, about)]
pub struct Args {
    /// Path to `cli.toml`. Default: `$XDG_CONFIG_HOME/vitonomi/cli.toml`.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a default `cli.toml`.
    Init {
        #[arg(long)]
        hub: Option<String>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Bootstrap a fresh cluster on the configured hub.
    Cluster(ClusterCmd),
    /// Run Scheme A login.
    Login,
    /// Revoke session + delete local state.
    Logout,
    /// Print current session, cluster, hub.
    Status,
    /// Vault directory + invite operations.
    Vault(VaultCmd),
    /// Record put / get / list / delete via the libp2p data plane.
    Record(RecordCmd),
    /// Credential operations (typed wrapper around Record + the
    /// per-RecordType `CredentialMetadata`/`CredentialBody` schemas).
    Credential(CredentialCmd),
    /// Cross-RecordType universal search.
    Search {
        query: String,
        /// Restrict to one or more record types. Default: every
        /// loaded type.
        #[arg(long, value_enum, value_delimiter = ',')]
        r#type: Option<Vec<RecordTypeArg>>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Debug, clap::Args)]
pub struct CredentialCmd {
    #[command(subcommand)]
    pub action: CredentialAction,
}

#[derive(Debug, Subcommand)]
pub enum CredentialAction {
    /// Add a new credential interactively (or scripted from a TOML
    /// file). Splits the input into the metadata + body faces and
    /// writes both.
    Add {
        /// Optional TOML file with `title`, `url`, `username`,
        /// `password`, `tags`, `folder`, `notes`. If omitted,
        /// prompts interactively.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// List every credential's metadata. Never fetches body chunks.
    List {
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        tag: Option<String>,
    },
    /// Show one credential. Metadata-only by default; `--reveal`
    /// triggers a body fetch and prints password / TOTP secret.
    Get {
        id: String,
        #[arg(long)]
        reveal: bool,
    },
    /// Edit one credential. Editing only metadata fields uses
    /// `BodyOp::Keep` and skips the body re-seal.
    Edit {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Tombstone a credential by id.
    Delete { id: String },
    /// Search credentials only (filtered subset of universal
    /// search).
    Search {
        query: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Print the current TOTP code for a credential. Body fetch
    /// required.
    Totp {
        id: String,
        /// Re-print the code each time the window rolls over.
        #[arg(long)]
        watch: bool,
    },
    /// Print a freshly-generated password to stdout. Pure-local, no
    /// hub round-trip.
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        strong: bool,
        #[arg(long)]
        exclude_ambiguous: bool,
    },
    /// Copy one of a credential's secrets to the system clipboard;
    /// auto-clears after `--auto-clear`. Falls back to stdout on
    /// headless hosts.
    Copy {
        id: String,
        #[arg(long, value_enum, default_value_t = CopyFieldArg::Password)]
        field: CopyFieldArg,
        /// e.g. `30s`, `1m`. Default 30 seconds.
        #[arg(long, default_value = "30s")]
        auto_clear: String,
    },
    /// Import credentials from a third-party export file.
    Import {
        #[arg(long, value_enum)]
        format: ImportFormatArg,
        file: PathBuf,
    },
    /// Export credentials.
    Export {
        #[arg(long, value_enum)]
        format: ExportFormatArg,
        file: PathBuf,
        /// For the `json` format only — explicitly opt into the
        /// plaintext export. Required (separately confirmed twice
        /// at the prompt).
        #[arg(long)]
        force_plain: bool,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum CopyFieldArg {
    Password,
    Totp,
    Username,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ImportFormatArg {
    OnePassword,
    Bitwarden,
    Chrome,
    Keepass,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ExportFormatArg {
    VitonomiBackup,
    Json,
}

impl ImportFormatArg {
    pub fn to_core(self) -> vitonomi_core::credentials::import::ImportFormat {
        use vitonomi_core::credentials::import::ImportFormat;
        match self {
            Self::OnePassword => ImportFormat::OnePasswordCsv,
            Self::Bitwarden => ImportFormat::BitwardenJson,
            Self::Chrome => ImportFormat::ChromeCsv,
            Self::Keepass => ImportFormat::KeepassXcCsv,
        }
    }
}

#[derive(Debug, clap::Args)]
pub struct RecordCmd {
    #[command(subcommand)]
    pub action: RecordAction,
}

#[derive(Debug, Subcommand)]
pub enum RecordAction {
    /// Upload a new record of the given type. The metadata face is
    /// the small searchable face that rides inline in the snapshot;
    /// the optional body face holds secrets / heavy bytes.
    Put {
        #[arg(value_enum)]
        rt: RecordTypeArg,
        /// File containing the metadata face bytes (typically
        /// deterministic CBOR). Required.
        #[arg(long)]
        metadata_file: PathBuf,
        /// File containing the body face bytes. Omit to write a
        /// metadata-only record.
        #[arg(long)]
        body_file: Option<PathBuf>,
    },
    /// Download one face of a record by id; defaults to stdout.
    Get {
        #[arg(value_enum)]
        rt: RecordTypeArg,
        id: String,
        /// Which face to fetch. `metadata` is cheap (no body chunks
        /// touched); `body` triggers a one-record body fetch.
        #[arg(long, value_enum, default_value_t = RecordFaceArg::Metadata)]
        face: RecordFaceArg,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// List every record of the given type. Metadata-only fetch —
    /// never touches body chunks.
    List {
        #[arg(value_enum)]
        rt: RecordTypeArg,
    },
    /// Tombstone a record by id. Body chunks become orphaned and
    /// are reclaimable by vault GC.
    Delete {
        #[arg(value_enum)]
        rt: RecordTypeArg,
        id: String,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RecordFaceArg {
    Metadata,
    Body,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RecordTypeArg {
    Credential,
    Alias,
    AliasMessage,
}

impl RecordTypeArg {
    fn to_core(self) -> vitonomi_core::record::RecordType {
        match self {
            Self::Credential => vitonomi_core::record::RecordType::Credential,
            Self::Alias => vitonomi_core::record::RecordType::Alias,
            Self::AliasMessage => vitonomi_core::record::RecordType::AliasMessage,
        }
    }
}

#[derive(Debug, clap::Args)]
pub struct ClusterCmd {
    #[command(subcommand)]
    pub action: ClusterAction,
}

#[derive(Debug, Subcommand)]
pub enum ClusterAction {
    Create {
        #[arg(long)]
        username: String,
    },
    Restore {
        #[arg(long)]
        username: String,
        #[arg(long)]
        chain_file: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
pub struct VaultCmd {
    #[command(subcommand)]
    pub action: VaultAction,
}

#[derive(Debug, Subcommand)]
pub enum VaultAction {
    Invite {
        #[arg(long)]
        name: String,
        /// Hub TLS cert SPKI fingerprint (`sha256:<base64url>`).
        /// Optional: defaults to `cli.toml`'s persisted
        /// `hub.cert_fingerprint` (auto-pinned by `cluster create`).
        /// Pass explicitly to override after a hub cert rotation.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Invite TTL in seconds. Default: 900 (15 minutes).
        #[arg(long, default_value_t = 900)]
        ttl: u64,
    },
    List,
}

/// Bin entrypoint. Parses argv from caller (so tests can drive
/// without mutating `std::env::args`).
///
/// # Errors
///
/// Surfaces config / network / persistence errors.
pub async fn run_cli<I, T>(argv: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = Args::parse_from(argv);
    crate::config::init_logging();
    let config_path = match args.config {
        Some(ref p) => p.clone(),
        None => crate::config::default_config_path()?,
    };
    match args.command {
        Command::Init {
            hub,
            state_dir,
            force,
        } => commands::init::run(Some(&config_path), hub, state_dir, force),
        Command::Cluster(c) => match c.action {
            ClusterAction::Create { username } => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                let mut prompts = InteractivePrompts;
                commands::cluster_create::run(
                    &cfg,
                    commands::cluster_create::ClusterCreateArgs {
                        config_path: &config_path,
                        state_path: &state_path,
                        username,
                        keyblob_argon2:
                            vitonomi_core::crypto::argon2::Argon2Params::default_for_env(),
                        lookup_argon2:
                            vitonomi_core::crypto::lookup_id::LookupIdParams::default_for_env(),
                        print_seed_phrase: true,
                    },
                    &mut prompts,
                )
                .await
            }
            ClusterAction::Restore {
                username,
                chain_file,
            } => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                let mut prompts = InteractivePrompts;
                commands::cluster_restore::run(
                    &cfg,
                    commands::cluster_restore::ClusterRestoreArgs {
                        state_path: &state_path,
                        username,
                        chain_export_path: &chain_file,
                        lookup_argon2:
                            vitonomi_core::crypto::lookup_id::LookupIdParams::default_for_env(),
                    },
                    &mut prompts,
                )
                .await
            }
        },
        Command::Login => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            let mut prompts = InteractivePrompts;
            commands::login::run(
                &cfg,
                commands::login::LoginArgs {
                    state_path: &state_path,
                    lookup_argon2:
                        vitonomi_core::crypto::lookup_id::LookupIdParams::default_for_env(),
                },
                &mut prompts,
            )
            .await
        }
        Command::Logout => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            commands::logout::run(&cfg, &state_path).await
        }
        Command::Status => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            commands::status::run(&cfg, &state_path)
        }
        Command::Vault(v) => match v.action {
            VaultAction::Invite {
                name,
                fingerprint,
                ttl,
            } => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                let resolved_fp = match fingerprint {
                    Some(fp) => fp,
                    None if !cfg.hub.cert_fingerprint.is_empty() => {
                        cfg.hub.cert_fingerprint.clone()
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "no hub.cert_fingerprint in cli.toml — \
                             re-run `cluster create` against the live hub, \
                             or pass `--fingerprint sha256:...` explicitly"
                        ));
                    }
                };
                let mut prompts = InteractivePrompts;
                commands::vault_invite::run(
                    &cfg,
                    commands::vault_invite::VaultInviteArgs {
                        state_path: &state_path,
                        vault_name: name,
                        hub_cert_fingerprint: resolved_fp,
                        ttl_secs: ttl,
                    },
                    &mut prompts,
                )
                .await
                .map(|_| ())
            }
            VaultAction::List => {
                let cfg = CliConfig::load(Some(&config_path))?;
                let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
                commands::vault_list::run(&cfg, &state_path).await
            }
        },
        Command::Record(r) => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            let mut prompts = InteractivePrompts;
            match r.action {
                RecordAction::Put {
                    rt,
                    metadata_file,
                    body_file,
                } => {
                    commands::record_put::run(
                        &cfg,
                        commands::record_put::RecordPutArgs {
                            state_path: &state_path,
                            record_type: rt.to_core(),
                            metadata_file,
                            body_file,
                        },
                        &mut prompts,
                    )
                    .await
                }
                RecordAction::Get { rt, id, face, out } => {
                    commands::record_get::run(
                        &cfg,
                        commands::record_get::RecordGetArgs {
                            state_path: &state_path,
                            record_type: rt.to_core(),
                            id_hex: id,
                            face: face.into(),
                            out,
                        },
                        &mut prompts,
                    )
                    .await
                }
                RecordAction::List { rt } => {
                    commands::record_list::run(
                        &cfg,
                        commands::record_list::RecordListArgs {
                            state_path: &state_path,
                            record_type: rt.to_core(),
                        },
                        &mut prompts,
                    )
                    .await
                }
                RecordAction::Delete { rt, id } => {
                    commands::record_delete::run(
                        &cfg,
                        commands::record_delete::RecordDeleteArgs {
                            state_path: &state_path,
                            record_type: rt.to_core(),
                            id_hex: id,
                        },
                        &mut prompts,
                    )
                    .await
                }
            }
        }
        Command::Credential(c) => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            let mut prompts = InteractivePrompts;
            match c.action {
                CredentialAction::Add { file } => {
                    commands::credential_add::run(
                        &cfg,
                        commands::credential_add::CredentialAddArgs {
                            state_path: &state_path,
                            file,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::List { folder, tag } => {
                    commands::credential_list::run(
                        &cfg,
                        commands::credential_list::CredentialListArgs {
                            state_path: &state_path,
                            folder,
                            tag,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Get { id, reveal } => {
                    commands::credential_get::run(
                        &cfg,
                        commands::credential_get::CredentialGetArgs {
                            state_path: &state_path,
                            id_hex: id,
                            reveal,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Edit {
                    id,
                    title,
                    url,
                    username,
                    folder,
                    password,
                    notes,
                } => {
                    commands::credential_edit::run(
                        &cfg,
                        commands::credential_edit::CredentialEditArgs {
                            state_path: &state_path,
                            id_hex: id,
                            title,
                            url,
                            username,
                            folder,
                            password,
                            notes,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Delete { id } => {
                    commands::credential_delete::run(
                        &cfg,
                        commands::credential_delete::CredentialDeleteArgs {
                            state_path: &state_path,
                            id_hex: id,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Search { query, limit } => {
                    commands::credential_search::run(
                        &cfg,
                        commands::credential_search::CredentialSearchArgs {
                            state_path: &state_path,
                            query,
                            limit,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Totp { id, watch } => {
                    commands::credential_totp::run(
                        &cfg,
                        commands::credential_totp::CredentialTotpArgs {
                            state_path: &state_path,
                            id_hex: id,
                            watch,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Generate {
                    length,
                    strong,
                    exclude_ambiguous,
                } => {
                    commands::credential_generate::run(
                        commands::credential_generate::CredentialGenerateArgs {
                            length,
                            strong,
                            exclude_ambiguous,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Copy {
                    id,
                    field,
                    auto_clear,
                } => {
                    commands::credential_copy::run(
                        &cfg,
                        commands::credential_copy::CredentialCopyArgs {
                            state_path: &state_path,
                            id_hex: id,
                            field,
                            auto_clear,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Import { format, file } => {
                    commands::credential_import::run(
                        &cfg,
                        commands::credential_import::CredentialImportArgs {
                            state_path: &state_path,
                            format: format.to_core(),
                            file,
                        },
                        &mut prompts,
                    )
                    .await
                }
                CredentialAction::Export {
                    format,
                    file,
                    force_plain,
                } => {
                    commands::credential_export::run(
                        &cfg,
                        commands::credential_export::CredentialExportArgs {
                            state_path: &state_path,
                            format,
                            file,
                            force_plain,
                        },
                        &mut prompts,
                    )
                    .await
                }
            }
        }
        Command::Search {
            query,
            r#type,
            limit,
        } => {
            let cfg = CliConfig::load(Some(&config_path))?;
            let state_path = state::resolve_state_path(state_dir_from_cfg(&cfg).as_deref())?;
            let mut prompts = InteractivePrompts;
            commands::search::run(
                &cfg,
                commands::search::SearchArgs {
                    state_path: &state_path,
                    query,
                    type_filter: r#type,
                    limit,
                },
                &mut prompts,
            )
            .await
        }
    }
}

fn state_dir_from_cfg(cfg: &CliConfig) -> Option<PathBuf> {
    if cfg.paths.state_dir.is_empty() {
        None
    } else {
        Some(PathBuf::from(&cfg.paths.state_dir))
    }
}
