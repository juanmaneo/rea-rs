//! Development tasks for the rea-rs workspace, following the
//! [cargo xtask](https://github.com/matklad/cargo-xtask) pattern.
//!
//! Run with `cargo xtask <TASK> [ARGS...]`. The `xtask` alias lives in
//! `.cargo/config.toml`. Tasks only drive the pinned toolchain; they never
//! install software.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;
use std::process::{Command, ExitCode, ExitStatus, Stdio};

const USAGE: &str = "\
Usage: cargo xtask <TASK> [ARGS...]

Tasks:
  check      type-check every workspace target
  fmt        format the workspace (pass --check to verify only)
  clippy     lint every workspace target, denying warnings
  test       run the workspace tests
  coverage   run the workspace tests under cargo-llvm-cov
  doc        build the workspace documentation, denying warnings
  ci         fmt --check, clippy, test, then doc

ARGS are forwarded to the underlying cargo command. For clippy, ARGS after
`--` are forwarded to the linter after `-D warnings`.
";

fn main() -> ExitCode {
    match parse(env::args_os().skip(1)) {
        Ok(Request::Help) => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Request::Run { task, args }) => match run(task, args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xtask: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("xtask: {error}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Task {
    Check,
    Fmt,
    Clippy,
    Test,
    Coverage,
    Doc,
    Ci,
}

impl Task {
    const ALL: [Task; 7] = [
        Task::Check,
        Task::Fmt,
        Task::Clippy,
        Task::Test,
        Task::Coverage,
        Task::Doc,
        Task::Ci,
    ];

    fn name(self) -> &'static str {
        match self {
            Task::Check => "check",
            Task::Fmt => "fmt",
            Task::Clippy => "clippy",
            Task::Test => "test",
            Task::Coverage => "coverage",
            Task::Doc => "doc",
            Task::Ci => "ci",
        }
    }

    fn from_name(name: &str) -> Option<Task> {
        Task::ALL.into_iter().find(|task| task.name() == name)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Request {
    Help,
    Run { task: Task, args: Vec<OsString> },
}

#[derive(Debug)]
enum UsageError {
    MissingTask,
    UnknownTask(String),
    UnexpectedArgs(Task),
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::MissingTask => f.write_str("missing task"),
            UsageError::UnknownTask(name) => write!(f, "unknown task `{name}`"),
            UsageError::UnexpectedArgs(task) => {
                write!(f, "`{}` does not accept extra arguments", task.name())
            }
        }
    }
}

fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Request, UsageError> {
    let first = args.next().ok_or(UsageError::MissingTask)?;
    let Some(name) = first.to_str() else {
        return Err(UsageError::UnknownTask(
            first.to_string_lossy().into_owned(),
        ));
    };
    if matches!(name, "help" | "-h" | "--help") {
        return Ok(Request::Help);
    }
    let task = Task::from_name(name).ok_or_else(|| UsageError::UnknownTask(name.to_owned()))?;
    let args: Vec<OsString> = args.collect();
    if task == Task::Ci && !args.is_empty() {
        return Err(UsageError::UnexpectedArgs(task));
    }
    Ok(Request::Run { task, args })
}

/// One cargo invocation run from the workspace root.
#[derive(Debug, PartialEq, Eq)]
struct Step {
    args: Vec<OsString>,
    deny_rustdoc_warnings: bool,
}

impl Step {
    fn new(base: &[&str], extra: impl IntoIterator<Item = OsString>) -> Step {
        let mut args: Vec<OsString> = base.iter().map(OsString::from).collect();
        args.extend(extra);
        Step {
            args,
            deny_rustdoc_warnings: false,
        }
    }

    fn display(&self) -> String {
        let mut line = String::from("cargo");
        for arg in &self.args {
            line.push(' ');
            line.push_str(&arg.to_string_lossy());
        }
        line
    }
}

fn steps(task: Task, extra: Vec<OsString>) -> Vec<Step> {
    match task {
        Task::Check => vec![Step::new(&["check", "--workspace", "--all-targets"], extra)],
        Task::Fmt => vec![Step::new(&["fmt", "--all"], extra)],
        Task::Clippy => vec![clippy(extra)],
        Task::Test => vec![Step::new(&["test", "--workspace"], extra)],
        Task::Coverage => vec![Step::new(&["llvm-cov", "--workspace"], extra)],
        Task::Doc => vec![doc(extra)],
        Task::Ci => vec![
            Step::new(&["fmt", "--all", "--check"], []),
            clippy(Vec::new()),
            Step::new(&["test", "--workspace"], []),
            doc(Vec::new()),
        ],
    }
}

fn clippy(extra: Vec<OsString>) -> Step {
    let split = extra.iter().position(|arg| arg == "--");
    let (cargo_args, lint_args) = match split {
        Some(index) => (&extra[..index], &extra[index + 1..]),
        None => (&extra[..], &[][..]),
    };
    let mut step = Step::new(
        &["clippy", "--workspace", "--all-targets"],
        cargo_args.to_vec(),
    );
    step.args
        .extend(["--", "-D", "warnings"].map(OsString::from));
    step.args.extend(lint_args.iter().cloned());
    step
}

fn doc(extra: Vec<OsString>) -> Step {
    let mut step = Step::new(&["doc", "--workspace", "--no-deps"], extra);
    step.deny_rustdoc_warnings = true;
    step
}

#[derive(Debug)]
enum RunError {
    Spawn(io::Error),
    Failed { command: String, status: ExitStatus },
    MissingCoverageTool,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunError::Spawn(source) => write!(f, "failed to start cargo: {source}"),
            RunError::Failed { command, status } => write!(f, "`{command}` failed ({status})"),
            RunError::MissingCoverageTool => f.write_str(
                "cargo-llvm-cov is not available; install it with \
                 `cargo install cargo-llvm-cov` (the llvm-tools component \
                 is pinned in rust-toolchain.toml)",
            ),
        }
    }
}

fn run(task: Task, extra: Vec<OsString>) -> Result<(), RunError> {
    // `cargo run` sets CARGO to the toolchain's cargo, keeping nested runs on the pinned toolchain.
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    if task == Task::Coverage && !has_coverage_tool(&cargo, &root) {
        return Err(RunError::MissingCoverageTool);
    }
    for step in steps(task, extra) {
        run_step(&cargo, &root, &step)?;
    }
    Ok(())
}

fn has_coverage_tool(cargo: &OsStr, root: &Path) -> bool {
    Command::new(cargo)
        .args(["llvm-cov", "--version"])
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn run_step(cargo: &OsStr, root: &Path, step: &Step) -> Result<(), RunError> {
    let command_line = step.display();
    eprintln!("$ {command_line}");
    let mut command = Command::new(cargo);
    command.args(&step.args).current_dir(root);
    if step.deny_rustdoc_warnings {
        let mut flags = env::var_os("RUSTDOCFLAGS").unwrap_or_default();
        if !flags.is_empty() {
            flags.push(" ");
        }
        flags.push("-D warnings");
        command.env("RUSTDOCFLAGS", flags);
    }
    let status = command.status().map_err(RunError::Spawn)?;
    if status.success() {
        Ok(())
    } else {
        Err(RunError::Failed {
            command: command_line,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn parse_args(args: &[&str]) -> Result<Request, UsageError> {
        parse(os(args).into_iter())
    }

    #[test]
    fn task_names_round_trip() {
        for task in Task::ALL {
            assert_eq!(Task::from_name(task.name()), Some(task));
        }
    }

    #[test]
    fn parses_task_and_forwards_arguments() {
        let request = parse_args(&["test", "-p", "xtask", "--", "--nocapture"]);
        assert_eq!(
            request.ok(),
            Some(Request::Run {
                task: Task::Test,
                args: os(&["-p", "xtask", "--", "--nocapture"]),
            })
        );
    }

    #[test]
    fn rejects_missing_unknown_and_overloaded_tasks() {
        assert!(matches!(parse_args(&[]), Err(UsageError::MissingTask)));
        assert!(matches!(
            parse_args(&["bench"]),
            Err(UsageError::UnknownTask(name)) if name == "bench"
        ));
        assert!(matches!(
            parse_args(&["ci", "--release"]),
            Err(UsageError::UnexpectedArgs(Task::Ci))
        ));
    }

    #[test]
    fn help_flags_request_usage() {
        for flag in ["help", "-h", "--help"] {
            assert_eq!(parse_args(&[flag]).ok(), Some(Request::Help));
        }
    }

    #[test]
    fn clippy_denies_warnings_and_splits_lint_arguments() {
        assert_eq!(
            clippy(os(&["-p", "xtask", "--", "-W", "clippy::pedantic"])).args,
            os(&[
                "clippy",
                "--workspace",
                "--all-targets",
                "-p",
                "xtask",
                "--",
                "-D",
                "warnings",
                "-W",
                "clippy::pedantic",
            ])
        );
        assert_eq!(
            clippy(Vec::new()).args,
            os(&[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings"
            ])
        );
    }

    #[test]
    fn ci_runs_read_only_gates_in_order() {
        let commands: Vec<String> = steps(Task::Ci, Vec::new())
            .iter()
            .map(Step::display)
            .collect();
        assert_eq!(
            commands,
            [
                "cargo fmt --all --check",
                "cargo clippy --workspace --all-targets -- -D warnings",
                "cargo test --workspace",
                "cargo doc --workspace --no-deps",
            ]
        );
        assert!(steps(Task::Doc, Vec::new())[0].deny_rustdoc_warnings);
    }
}
