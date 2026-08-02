use std::process::ExitCode;

fn main() -> ExitCode {
    match pkgscope::cli::run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!(
                "pkgscope: {}",
                pkgscope::sanitize::terminal_text(&format!("{error:#}"))
            );
            ExitCode::from(1)
        }
    }
}
