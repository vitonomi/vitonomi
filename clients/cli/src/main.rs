use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match vitonomi_cli::cli::run_cli(std::env::args_os()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vitonomi-cli: {e:#}");
            ExitCode::from(1)
        }
    }
}
