use std::process::ExitCode;

/// Usage: mask-browser [ADDRESS]
/// ADDRESS may be a website (https://…) or a morp://<id>.morp address.
fn main() -> ExitCode {
    let initial = std::env::args().nth(1);
    match mask::browser::run(initial.as_deref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("MASK Browser failed to start: {err}");
            ExitCode::FAILURE
        }
    }
}
