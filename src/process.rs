use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;
use wait_timeout::ChildExt;

pub const DEFAULT_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
static CANCELLED: AtomicBool = AtomicBool::new(false);
static CANCEL_HANDLER: OnceLock<Result<(), String>> = OnceLock::new();

pub fn install_cancel_handler() -> Result<(), String> {
    CANCELLED.store(false, Ordering::SeqCst);
    CANCEL_HANDLER
        .get_or_init(|| {
            ctrlc::set_handler(|| {
                CANCELLED.store(true, Ordering::SeqCst);
            })
            .map_err(|error| error.to_string())
        })
        .clone()
}

pub fn cancel_requested() -> bool {
    CANCELLED.load(Ordering::SeqCst)
}

pub fn clear_cancel() {
    CANCELLED.store(false, Ordering::SeqCst);
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, String>,
    pub timeout: Duration,
    pub output_limit: usize,
    pub clear_env: bool,
}

impl CommandSpec {
    pub fn new(executable: impl Into<PathBuf>, args: &[&str], timeout: Duration) -> Self {
        Self {
            executable: executable.into(),
            args: args.iter().map(|v| (*v).to_string()).collect(),
            cwd: None,
            env: BTreeMap::new(),
            timeout,
            output_limit: DEFAULT_OUTPUT_LIMIT,
            clear_env: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub struct CommandAttempt {
    pub output: CommandOutput,
    pub status: ExitStatus,
}

impl CommandOutput {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("could not start {executable}: {source}")]
    Spawn {
        executable: String,
        #[source]
        source: std::io::Error,
    },
    #[error("command timed out after {0:?}")]
    TimedOut(Duration),
    #[error("command was cancelled")]
    Cancelled,
    #[error("command exited unsuccessfully ({status}): {stderr}")]
    Failed { status: String, stderr: String },
    #[error("command output exceeded the {limit} byte safety limit")]
    OutputLimit { limit: usize },
    #[error("could not collect command output: {0}")]
    Io(#[from] std::io::Error),
}

pub fn run(spec: &CommandSpec) -> Result<CommandOutput, CommandError> {
    let attempt = run_allow_failure(spec)?;
    if !attempt.status.success() {
        return Err(CommandError::Failed {
            status: attempt
                .status
                .code()
                .map_or_else(|| "terminated by signal".into(), |code| code.to_string()),
            stderr: redact_diagnostic(&String::from_utf8_lossy(&attempt.output.stderr)),
        });
    }
    Ok(attempt.output)
}

pub fn run_allow_failure(spec: &CommandSpec) -> Result<CommandAttempt, CommandError> {
    let mut command = Command::new(&spec.executable);
    if spec.clear_env {
        command.env_clear();
    }
    command
        .args(&spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(&spec.env);
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }

    let mut child = command.spawn().map_err(|source| CommandError::Spawn {
        executable: spec.executable.display().to_string(),
        source,
    })?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let limit = spec.output_limit;
    let limit_exceeded = Arc::new(AtomicBool::new(false));
    let stdout_flag = Arc::clone(&limit_exceeded);
    let stderr_flag = Arc::clone(&limit_exceeded);
    let stdout_reader = thread::spawn(move || read_bounded(stdout, limit, stdout_flag));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, limit, stderr_flag));

    let deadline = Instant::now() + spec.timeout;
    let status = loop {
        if cancel_requested() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(CommandError::Cancelled);
        }
        if limit_exceeded.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(CommandError::OutputLimit { limit });
        }
        let now = Instant::now();
        if now >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(CommandError::TimedOut(spec.timeout));
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(25));
        if let Some(status) = child.wait_timeout(wait)? {
            break status;
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| std::io::Error::other("stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| std::io::Error::other("stderr reader panicked"))??;
    if stdout.truncated || stderr.truncated {
        return Err(CommandError::OutputLimit { limit });
    }
    Ok(CommandAttempt {
        output: CommandOutput {
            stdout: stdout.bytes,
            stderr: stderr.bytes,
        },
        status,
    })
}

struct BoundedRead {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded(
    mut input: impl Read,
    limit: usize,
    limit_exceeded: Arc<AtomicBool>,
) -> std::io::Result<BoundedRead> {
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
        if count > remaining {
            truncated = true;
            limit_exceeded.store(true, Ordering::Relaxed);
        }
    }
    Ok(BoundedRead { bytes, truncated })
}

pub(crate) fn redact_diagnostic(value: &str) -> String {
    let shortened = value.lines().take(8).collect::<Vec<_>>().join(" ");
    let mut result = Vec::new();
    let mut redact_next = false;
    for word in shortened.split_whitespace().take(80) {
        let lower = word.to_ascii_lowercase();
        if redact_next {
            result.push("[redacted]");
            redact_next = false;
        } else if lower.trim_matches(|ch: char| !ch.is_ascii_alphanumeric()) == "bearer" {
            result.push("[redacted]");
            redact_next = true;
        } else if ["token", "password", "passwd", "secret", "_auth"]
            .iter()
            .any(|marker| lower.contains(marker))
            && (lower.contains('=') || lower.contains(':'))
        {
            result.push("[redacted]");
        } else {
            result.push(redact_url_userinfo(word));
        }
    }
    crate::sanitize::terminal_text(&result.join(" "))
}

fn redact_url_userinfo(value: &str) -> &str {
    let Some(scheme_end) = value.find("://") else {
        return value;
    };
    let authority = &value[scheme_end + 3..];
    let Some(_at) = authority.find('@') else {
        return value;
    };
    "[redacted-url]"
}

pub fn find_executables(name: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    if name.contains(std::path::MAIN_SEPARATOR) {
        let path = PathBuf::from(name);
        if is_executable(&path) {
            found.push(path);
        }
        return found;
    }
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let candidate = directory.join(name);
            if is_executable(&candidate) && !same_path_in(&found, &candidate) {
                found.push(candidate);
            }
        }
    }
    found
}

fn same_path_in(paths: &[PathBuf], candidate: &Path) -> bool {
    let canonical = candidate
        .canonicalize()
        .unwrap_or_else(|_| candidate.to_path_buf());
    paths.iter().any(|path| {
        path.canonicalize().unwrap_or_else(|_| path.clone()) == canonical || path == candidate
    })
}

#[cfg(unix)]
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_argv_does_not_invoke_a_shell() {
        let spec = CommandSpec::new("/bin/echo", &["$(printf unsafe)"], Duration::from_secs(1));
        let output = run(&spec).unwrap();
        assert_eq!(output.stdout_text().trim(), "$(printf unsafe)");
    }

    #[test]
    fn output_is_bounded() {
        let mut spec = CommandSpec::new("/usr/bin/yes", &[], Duration::from_secs(2));
        spec.output_limit = 1024;
        assert!(matches!(run(&spec), Err(CommandError::OutputLimit { .. })));
    }

    #[test]
    fn commands_are_terminated_at_the_timeout() {
        let spec = CommandSpec::new("/bin/sleep", &["2"], Duration::from_millis(10));
        assert!(matches!(run(&spec), Err(CommandError::TimedOut(_))));
    }

    #[test]
    fn diagnostics_redact_common_credential_forms() {
        let redacted = redact_diagnostic(
            "Authorization: Bearer very-secret token=also-secret https://user:pass@example.test/x",
        );
        assert!(!redacted.contains("very-secret"));
        assert!(!redacted.contains("also-secret"));
        assert!(!redacted.contains("user:pass"));
    }
}
