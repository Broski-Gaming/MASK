use std::process::ExitCode;

/// Usage: mask-browser [ADDRESS]
/// ADDRESS may be a website (https://…) or a morp://<id>.morp address.
///
/// Environment: MASK_NETWORK (testnet), MASK_MORP_ONLY=1 (refuse all
/// websites), MASK_STATE_DIR (entry guards), MASK_KEEP_TIMEZONE=1 (do not
/// force UTC), plus the local-mode variables documented in `morp.rs`.
fn main() -> ExitCode {
    // Pages can read the time zone (Date, Intl), which narrows down where
    // the user is. WebKit's web processes inherit this. Set before any
    // thread exists (setting the environment is only safe then).
    if std::env::var_os("MASK_KEEP_TIMEZONE").is_none() {
        // SAFETY: first statement of main; no other threads are running.
        unsafe { std::env::set_var("TZ", mask::privacy::TIME_ZONE) };
    }
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
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
