use std::process::ExitCode;

fn main() -> ExitCode {
    match mask::browser::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("MASK Browser failed to start: {err}");
            ExitCode::FAILURE
        }
    }
}
