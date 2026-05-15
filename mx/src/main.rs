//! `vitonomi-mx` binary entrypoint. Thin shell that parses argv
//! and delegates to [`vitonomi_mx::cli::run_cli`]. Real work lives
//! in the library so integration tests can drive `run` without a
//! subprocess.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match vitonomi_mx::cli::run_cli().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vitonomi-mx: {e:#}");
            ExitCode::from(1)
        }
    }
}
