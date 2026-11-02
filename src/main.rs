use std::process::ExitCode;

/// Usage: mask-browser [ADDRESS]
/// ADDRESS may be a website (https://…) or a morp://<id>.morp address.
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,mask=info".into()),
        )
        .init();
    let initial = std::env::args().nth(1);
    match mask::browser::run(initial.as_deref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("MASK Browser failed to start: {err}");
            ExitCode::FAILURE
        }
    }
}
