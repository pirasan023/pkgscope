use std::{
    collections::{BTreeMap, BTreeSet},
    io::{IsTerminal, stdin, stdout},
    path::PathBuf,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{
    model::{
        InstallType, InstallationRecord, ManagerKind, RemovalAction, RemovalPlan, Severity,
        Snapshot,
    },
    output::{self, OutputFormat, SortField, SortOrder},
    scanner::{self, ScanOptions},
    state::StateStore,
};

#[derive(Debug, Parser)]
#[command(
    name = "pkgscope",
    version,
    disable_help_subcommand = true,
    about = "Inspect and uninstall developer tools from one terminal UI",
    long_about = "Scan supported package managers, inspect installed developer tools, and uninstall with typed confirmation from one terminal UI."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    common: CommonOptions,
}

#[derive(Debug, Args, Clone)]
pub(crate) struct CommonOptions {
    /// Restrict scanning/output to a manager (repeatable)
    #[arg(long, global = true, value_name = "NAME", hide = true)]
    manager: Vec<ManagerKind>,

    /// Restrict output to a manager instance ID or environment label (repeatable)
    #[arg(long, global = true, value_name = "ID", hide = true)]
    environment: Vec<String>,

    /// Discover additional standard runtime-manager locations
    #[arg(long, global = true, hide = true)]
    all_environments: bool,

    /// Ignore the latest saved snapshot and perform a fresh scan
    #[arg(long, global = true)]
    refresh: bool,

    /// Prohibit optional network features (manager inventory is local regardless)
    #[arg(long, global = true, hide = true)]
    offline: bool,

    /// Timeout for each manager command, such as 10s or 500ms
    #[arg(long, global = true, value_parser = crate::config::parse_duration, hide = true)]
    timeout: Option<Duration>,

    /// Opt in to history evidence (accepted but not read by the v0.3 scanner)
    #[arg(long, global = true, hide = true)]
    history: bool,

    /// Opt in to a project root (accepted but not read by the v0.3 scanner)
    #[arg(long, global = true, value_name = "PATH", hide = true)]
    project_root: Vec<PathBuf>,

    /// Output format
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    /// Color policy (state is always also represented by text)
    #[arg(long, global = true, value_enum, hide = true)]
    color: Option<ColorChoice>,

    /// Suppress non-essential diagnostics
    #[arg(long, global = true, conflicts_with = "verbose", hide = true)]
    quiet: bool,

    /// Include additional scanner diagnostics
    #[arg(long, global = true, hide = true)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Open the interactive terminal interface
    Tui,
    /// Perform a fresh scan and save a snapshot
    #[command(hide = true)]
    Scan,
    /// List managed installations
    List(ListOptions),
    /// Inspect one stable ID or an unambiguous exact package name
    #[command(hide = true)]
    Inspect { target: String },
    /// List installations by owned allocated size
    #[command(hide = true)]
    Largest,
    /// List all findings
    #[command(hide = true)]
    Findings {
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
    },
    /// List duplicate_package findings
    #[command(hide = true)]
    Duplicates,
    /// List command_collision and shadowed_command findings
    #[command(hide = true)]
    Conflicts,
    /// List broken findings
    #[command(hide = true)]
    Broken,
    /// Print an audit summary
    #[command(hide = true)]
    Audit {
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,
        #[arg(long, value_name = "CODE")]
        fail_on: Vec<String>,
    },
    /// Show a manager-native removal plan; never execute it
    #[command(hide = true)]
    RemovalPlan {
        target: String,
        #[arg(long, value_enum, default_value_t = PlanFormat::Human)]
        plan_format: PlanFormat,
    },
    /// Diagnose state storage, manager discovery, PATH, and platform support
    Doctor,
    /// Preserve and reset pkgscope's local snapshot state
    #[command(hide = true)]
    Reset,
}

#[derive(Debug, Args)]
struct ListOptions {
    #[arg(long, value_enum)]
    sort: Option<SortField>,
    #[arg(long, value_enum)]
    order: Option<SortOrder>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PlanFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SeverityArg {
    Info,
    Review,
    Warning,
    Critical,
}

impl From<SeverityArg> for Severity {
    fn from(value: SeverityArg) -> Self {
        match value {
            SeverityArg::Info => Self::Info,
            SeverityArg::Review => Self::Review,
            SeverityArg::Warning => Self::Warning,
            SeverityArg::Critical => Self::Critical,
        }
    }
}

pub fn run() -> Result<u8> {
    crate::process::install_cancel_handler()
        .map_err(|error| anyhow::anyhow!("could not install Ctrl+C handler: {error}"))?;
    let mut cli = Cli::parse();
    let config = match crate::config::Config::load_default() {
        Ok(config) => config,
        Err(error) => {
            eprintln!(
                "pkgscope: configuration error: {}",
                crate::sanitize::terminal_text(&format!("{error:#}"))
            );
            return Ok(2);
        }
    };
    if let Err(error) = resolve_config(&mut cli, &config) {
        eprintln!(
            "pkgscope: configuration error: {}",
            crate::sanitize::terminal_text(&format!("{error:#}"))
        );
        return Ok(2);
    }
    output::set_color_enabled(match cli.common.color.unwrap_or(ColorChoice::Auto) {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => std::env::var_os("NO_COLOR").is_none() && stdout().is_terminal(),
    });
    let default_sort = SortField::from(config.ui.default_sort);
    let default_order = SortOrder::from(config.ui.default_order);
    if (cli.common.history || !cli.common.project_root.is_empty()) && !cli.common.quiet {
        eprintln!(
            "notice: history and project evidence are not read by the v0.3 scanner; no history or project file content was accessed"
        );
    }
    if matches!(cli.command, Some(Command::Reset)) {
        return match crate::state::reset()? {
            Some(path) => {
                println!(
                    "State was reset. The previous database is preserved at {}.",
                    crate::sanitize::terminal_text(&path.display().to_string())
                );
                Ok(0)
            }
            None => {
                println!("No pkgscope state database exists; nothing changed.");
                Ok(0)
            }
        };
    }
    if matches!(cli.command, Some(Command::Doctor)) {
        if !matches!(cli.common.format, OutputFormat::Table | OutputFormat::Json) {
            eprintln!("pkgscope: doctor supports --format table or json");
            return Ok(2);
        }
        return doctor(&cli.common, &config);
    }

    let mut store = match StateStore::open_default_with_policy(
        config.storage.max_snapshots,
        config.storage.max_age_days,
    ) {
        Ok(store) => Some(store),
        Err(error) => {
            if !cli.common.quiet {
                eprintln!(
                    "warning: snapshots cannot be persisted: {}",
                    crate::sanitize::terminal_text(&format!("{error:#}"))
                );
            }
            None
        }
    };
    let opening_tui = matches!(cli.command, Some(Command::Tui))
        || (cli.command.is_none() && stdout().is_terminal() && stdin().is_terminal());
    let force_scan = opening_tui
        || matches!(cli.command, Some(Command::Scan))
        || cli.common.refresh
        || cli.common.all_environments
        || !cli.common.manager.is_empty();
    let mut snapshot = if force_scan {
        fresh_snapshot(&cli.common, store.as_mut())
    } else {
        match store
            .as_ref()
            .and_then(|store| store.latest().ok())
            .flatten()
        {
            Some(snapshot) if cache_matches_request(&snapshot, &cli.common) => snapshot,
            None => fresh_snapshot(&cli.common, store.as_mut()),
            Some(_) => fresh_snapshot(&cli.common, store.as_mut()),
        }
    };
    if crate::process::cancel_requested() {
        eprintln!("Scan cancelled; no snapshot was saved.");
        return Ok(1);
    }
    filter_snapshot(&mut snapshot, &cli.common);
    let partial_code = if snapshot.partial { 3 } else { 0 };

    match cli.command {
        None if stdout().is_terminal() && stdin().is_terminal() => crate::tui::run(
            snapshot,
            cli.common.clone(),
            store,
            default_sort,
            default_order,
        ),
        None => {
            output::installations(&snapshot, cli.common.format, default_sort, default_order)?;
            Ok(partial_code)
        }
        Some(Command::Tui) => crate::tui::run(
            snapshot,
            cli.common.clone(),
            store,
            default_sort,
            default_order,
        ),
        Some(Command::Scan) => {
            output::installations(&snapshot, cli.common.format, default_sort, default_order)?;
            Ok(partial_code)
        }
        Some(Command::List(options)) => {
            output::installations(
                &snapshot,
                cli.common.format,
                options.sort.unwrap_or(default_sort),
                options.order.unwrap_or(default_order),
            )?;
            Ok(partial_code)
        }
        Some(Command::Largest) => {
            output::installations(
                &snapshot,
                cli.common.format,
                SortField::Size,
                SortOrder::Desc,
            )?;
            Ok(partial_code)
        }
        Some(Command::Inspect { target }) => inspect_command(&snapshot, &target, cli.common.format),
        Some(Command::Findings { severity }) => {
            let minimum = severity.map(Severity::from);
            let findings: Vec<_> = snapshot
                .findings
                .iter()
                .filter(|finding| minimum.is_none_or(|minimum| finding.severity >= minimum))
                .collect();
            output::findings(&snapshot, &findings, cli.common.format)?;
            Ok(partial_code)
        }
        Some(Command::Duplicates) => finding_command(
            &snapshot,
            &["duplicate_package"],
            cli.common.format,
            partial_code,
        ),
        Some(Command::Conflicts) => finding_command(
            &snapshot,
            &["command_collision", "shadowed_command"],
            cli.common.format,
            partial_code,
        ),
        Some(Command::Broken) => finding_command(
            &snapshot,
            &["broken_command", "broken_runtime", "broken_owner_metadata"],
            cli.common.format,
            partial_code,
        ),
        Some(Command::Audit { severity, fail_on }) => {
            if !matches!(cli.common.format, OutputFormat::Table | OutputFormat::Json) {
                eprintln!("pkgscope: audit supports --format table or json");
                return Ok(2);
            }
            let minimum = severity.map(Severity::from);
            let mut view = snapshot.clone();
            if let Some(minimum) = minimum {
                view.findings.retain(|finding| finding.severity >= minimum);
            }
            output::audit(&view, cli.common.format)?;
            let policy_failed = !fail_on.is_empty()
                && snapshot
                    .findings
                    .iter()
                    .any(|finding| fail_on.contains(&finding.code));
            Ok(if policy_failed { 10 } else { partial_code })
        }
        Some(Command::RemovalPlan {
            target,
            plan_format,
        }) => {
            let record = match unique_record(&snapshot, &target) {
                Ok(record) => record,
                Err(code) => return Ok(code),
            };
            match build_removal_plan(&snapshot, record) {
                Ok(plan) => {
                    if matches!(cli.common.format, OutputFormat::Csv | OutputFormat::Jsonl) {
                        eprintln!("pkgscope: removal-plan supports --format table or json");
                        return Ok(2);
                    }
                    output::removal_plan(
                        &plan,
                        matches!(plan_format, PlanFormat::Json)
                            || cli.common.format == OutputFormat::Json,
                    )?;
                    Ok(partial_code)
                }
                Err(error) => {
                    eprintln!(
                        "pkgscope: {}",
                        crate::sanitize::terminal_text(&error.to_string())
                    );
                    Ok(5)
                }
            }
        }
        Some(Command::Doctor | Command::Reset) => unreachable!(),
    }
}

fn cache_matches_request(snapshot: &Snapshot, common: &CommonOptions) -> bool {
    snapshot.schema_version == crate::model::SCHEMA_VERSION
        && snapshot.scope.requested_managers.is_empty()
        && common.manager.is_empty()
        && snapshot.scope.environment_mode
            == if common.all_environments {
                crate::model::EnvironmentMode::Deep
            } else {
                crate::model::EnvironmentMode::Active
            }
        && !snapshot.scope.history_enabled
        && snapshot.scope.project_roots.is_empty()
}

fn fresh_snapshot(common: &CommonOptions, store: Option<&mut StateStore>) -> Snapshot {
    if !common.quiet {
        eprintln!("Scanning supported manager instances…");
    }
    let mut snapshot = scanner::scan(&scan_options(common));
    if crate::process::cancel_requested() {
        return snapshot;
    }
    if let Some(store) = store
        && let Err(error) = store.save(&mut snapshot)
    {
        eprintln!(
            "warning: scan succeeded but the snapshot could not be saved: {}",
            crate::sanitize::terminal_text(&format!("{error:#}"))
        );
    }
    if !common.quiet {
        for instance in &snapshot.manager_instances {
            eprintln!(
                "{} {} — {:?}",
                instance.manager, instance.executable_path, instance.scan_status
            );
        }
    }
    snapshot
}

pub(crate) fn scan_options(common: &CommonOptions) -> ScanOptions {
    ScanOptions {
        managers: common.manager.clone(),
        all_environments: common.all_environments,
        timeout: common.timeout.unwrap_or(Duration::from_secs(10)),
        calculate_sizes: true,
        // v0.3 intentionally does not read either opt-in source yet.
        history: false,
        project_roots: Vec::new(),
        verbose: common.verbose,
        offline: common.offline,
    }
}

fn resolve_config(cli: &mut Cli, config: &crate::config::Config) -> Result<()> {
    if cli.common.timeout.is_none() {
        cli.common.timeout = Some(config.timeout()?);
    }
    if !cli.common.all_environments
        && config.scan.default_environment_mode == crate::config::EnvironmentModeConfig::Deep
    {
        cli.common.all_environments = true;
    }
    if !cli.common.history {
        cli.common.history = config.scan.history;
    }
    if cli.common.project_root.is_empty() {
        cli.common.project_root = config.scan.project_roots.clone();
    }
    if cli.common.color.is_none() {
        cli.common.color = Some(match config.ui.color {
            crate::config::ColorConfig::Auto => ColorChoice::Auto,
            crate::config::ColorConfig::Always => ColorChoice::Always,
            crate::config::ColorConfig::Never => ColorChoice::Never,
        });
    }
    Ok(())
}

pub(crate) fn filter_snapshot(snapshot: &mut Snapshot, common: &CommonOptions) {
    let managers: BTreeSet<_> = common.manager.iter().copied().collect();
    if !managers.is_empty() {
        snapshot
            .manager_instances
            .retain(|instance| managers.contains(&instance.manager));
    }
    let allowed_instances: BTreeSet<_> = snapshot
        .manager_instances
        .iter()
        .filter(|instance| {
            common.environment.is_empty()
                || common.environment.contains(&instance.id)
                || common
                    .environment
                    .contains(&crate::scanner::environment_label(instance))
                || instance
                    .runtime_manager
                    .as_ref()
                    .is_some_and(|environment| common.environment.contains(environment))
                || instance
                    .root
                    .as_ref()
                    .is_some_and(|environment| common.environment.contains(environment))
        })
        .map(|instance| instance.id.clone())
        .collect();
    snapshot
        .manager_instances
        .retain(|instance| allowed_instances.contains(&instance.id));
    snapshot
        .installations
        .retain(|record| allowed_instances.contains(&record.manager_instance_id));
    let allowed_installations: BTreeSet<_> = snapshot
        .installations
        .iter()
        .map(|record| record.id.clone())
        .collect();
    snapshot
        .commands
        .retain(|command| allowed_installations.contains(&command.owner_installation_id));
    snapshot.findings.retain(|finding| {
        finding.installation_ids.is_empty()
            || finding
                .installation_ids
                .iter()
                .any(|id| allowed_installations.contains(id))
    });
    snapshot.errors.retain(|error| {
        error.manager_instance_id.is_none()
            || error
                .manager_instance_id
                .as_ref()
                .is_some_and(|id| allowed_instances.contains(id))
    });
    crate::analysis::apply_findings(snapshot);
    snapshot.partial = !snapshot.errors.is_empty()
        || snapshot
            .manager_instances
            .iter()
            .any(|instance| instance.scan_status != crate::model::ScanStatus::Success);
}

fn inspect_command(snapshot: &Snapshot, target: &str, format: OutputFormat) -> Result<u8> {
    if !matches!(format, OutputFormat::Table | OutputFormat::Json) {
        eprintln!("pkgscope: inspect supports --format table or json");
        return Ok(2);
    }
    let record = match unique_record(snapshot, target) {
        Ok(record) => record,
        Err(code) => return Ok(code),
    };
    output::inspect(snapshot, record, format)?;
    Ok(if snapshot.partial { 3 } else { 0 })
}

fn unique_record<'a>(
    snapshot: &'a Snapshot,
    target: &str,
) -> std::result::Result<&'a InstallationRecord, u8> {
    if let Some(record) = snapshot
        .installations
        .iter()
        .find(|record| record.id == target)
    {
        return Ok(record);
    }
    let matches: Vec<_> = snapshot
        .installations
        .iter()
        .filter(|record| record.identity.name == target)
        .collect();
    match matches.as_slice() {
        [record] => Ok(record),
        [] => {
            eprintln!(
                "pkgscope: no installation matches {:?}",
                crate::sanitize::terminal_text(target)
            );
            Err(4)
        }
        records => {
            eprintln!(
                "pkgscope: {:?} is ambiguous; use a stable ID:",
                crate::sanitize::terminal_text(target)
            );
            for record in records {
                eprintln!(
                    "  {}  {}  {}",
                    record.id,
                    record.environment,
                    record.version.value.as_deref().unwrap_or("Unknown")
                );
            }
            Err(4)
        }
    }
}

fn finding_command(
    snapshot: &Snapshot,
    codes: &[&str],
    format: OutputFormat,
    exit_code: u8,
) -> Result<u8> {
    let findings: Vec<_> = snapshot
        .findings
        .iter()
        .filter(|finding| codes.contains(&finding.code.as_str()))
        .collect();
    output::findings(snapshot, &findings, format)?;
    Ok(exit_code)
}

pub fn build_removal_plan(snapshot: &Snapshot, record: &InstallationRecord) -> Result<RemovalPlan> {
    if !record.removal_plan_available || record.install_type == InstallType::Injected {
        anyhow::bail!("this record has no independent manager-native removal plan");
    }
    let instance = output::manager_for(snapshot, record)
        .context("the owning manager instance is missing from this snapshot")?;
    let mut env_overrides = BTreeMap::new();
    let mut argv: Vec<String> = match instance.manager {
        ManagerKind::Brew => {
            if record.identity.source_kind == crate::model::SourceKind::Cask {
                vec![
                    "uninstall".into(),
                    "--cask".into(),
                    record.identity.name.clone(),
                ]
            } else {
                vec!["uninstall".into(), record.identity.name.clone()]
            }
        }
        ManagerKind::Npm => vec![
            "uninstall".into(),
            "-g".into(),
            record.identity.name.clone(),
        ],
        ManagerKind::Pnpm => vec!["remove".into(), "-g".into(), record.identity.name.clone()],
        ManagerKind::Pipx => vec!["uninstall".into(), record.identity.name.clone()],
        ManagerKind::Uv => vec![
            "tool".into(),
            "uninstall".into(),
            record.identity.name.clone(),
        ],
        ManagerKind::Cargo => {
            if let Some(root) = &instance.root {
                env_overrides.insert("CARGO_INSTALL_ROOT".into(), root.clone());
            }
            vec!["uninstall".into(), record.identity.name.clone()]
        }
        ManagerKind::Apt => vec![
            "--assume-yes".into(),
            "--no-auto-remove".into(),
            "remove".into(),
            "--".into(),
            record.identity.name.clone(),
        ],
        ManagerKind::Dnf => vec![
            "--assumeyes".into(),
            "--setopt=clean_requirements_on_remove=False".into(),
            "remove".into(),
            record
                .metadata
                .get("rpm_name_arch")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&record.identity.name)
                .to_string(),
        ],
        ManagerKind::Pacman => vec![
            "-R".into(),
            "--noconfirm".into(),
            "--".into(),
            record.identity.name.clone(),
        ],
        ManagerKind::Snap => vec!["remove".into(), record.identity.name.clone()],
        ManagerKind::Flatpak => {
            let installation = record
                .metadata
                .get("flatpak_installation")
                .and_then(serde_json::Value::as_str)
                .context("Flatpak installation scope is missing")?;
            let reference = record
                .metadata
                .get("flatpak_ref")
                .and_then(serde_json::Value::as_str)
                .context("Flatpak installed ref is missing")?;
            let mut args = crate::scanner::flatpak::scope_args(installation);
            args.extend([
                "uninstall".into(),
                "--noninteractive".into(),
                "--no-related".into(),
                reference.into(),
            ]);
            args
        }
    };
    let managed_dependents = reverse_dependents(snapshot, record);
    let mut warnings = Vec::new();
    if !managed_dependents.is_empty() {
        warnings.push("This manager reports installed records that depend on the target.".into());
    }
    if snapshot.findings.iter().any(|finding| {
        finding.code == "command_collision" && finding.installation_ids.contains(&record.id)
    }) {
        warnings
            .push("Another installation exposes at least one of the same command names.".into());
    }
    if record.identity.name == "pkgscope" {
        warnings.push("pkgscope self-uninstall is blocked before manager execution.".into());
    }
    let requires_root = record
        .metadata
        .get("requires_root")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if requires_root {
        let reason = record
            .metadata
            .get("privilege_reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("the owning manager modifies a system installation");
        warnings.push(format!(
            "Root privileges are required because {reason}. pkgscope never starts sudo automatically."
        ));
    }
    let mut related_data_excluded = vec![
        "manager shared caches and stores".into(),
        "user configuration and logs".into(),
    ];
    if instance.manager == ManagerKind::Brew
        && record.identity.source_kind == crate::model::SourceKind::Cask
    {
        related_data_excluded
            .push("Homebrew cask zap artifacts (--zap is never planned by default)".into());
    }
    if instance.manager == ManagerKind::Snap {
        related_data_excluded
            .push("Snap user and system data (remove --purge is never used)".into());
    }
    if instance.manager == ManagerKind::Flatpak {
        related_data_excluded
            .push("Flatpak per-application user data (--delete-data is never used)".into());
        related_data_excluded.push("Related runtimes (--no-related is always used)".into());
    }
    // Keep argv plainly structured. TUI execution passes it directly to the owning manager.
    argv.shrink_to_fit();
    Ok(RemovalPlan {
        installation_id: record.id.clone(),
        manager_instance_id: instance.id.clone(),
        target_name: record.identity.name.clone(),
        target_version: record.version.value.clone(),
        preconditions: {
            let mut preconditions = vec![
                "identity_unchanged".into(),
                "owner_unchanged".into(),
                "not_current_process_or_required_runtime".into(),
            ];
            if matches!(
                instance.manager,
                ManagerKind::Apt | ManagerKind::Dnf | ManagerKind::Pacman
            ) {
                preconditions.push("removal_transaction_contains_only_target".into());
            }
            if requires_root {
                preconditions.push("already_running_with_root_privileges".into());
            }
            preconditions
        },
        managed_dependents,
        warnings,
        action: RemovalAction {
            executable: instance.executable_path.clone(),
            argv,
            cwd: None,
            env_overrides,
        },
        related_data_excluded,
        rollback_supported: false,
    })
}

fn reverse_dependents(snapshot: &Snapshot, target: &InstallationRecord) -> Vec<String> {
    let mut dependents = snapshot
        .installations
        .iter()
        .filter(|candidate| candidate.manager_instance_id == target.manager_instance_id)
        .filter(|candidate| {
            candidate
                .metadata
                .get("dependencies")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|dependencies| {
                    dependencies
                        .iter()
                        .any(|dependency| dependency.as_str() == Some(&target.identity.name))
                })
        })
        .map(|record| record.identity.name.clone())
        .collect::<Vec<_>>();
    dependents.extend(
        target
            .metadata
            .get("required_by")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string),
    );
    dependents.sort();
    dependents.dedup();
    dependents
}

fn doctor(common: &CommonOptions, config: &crate::config::Config) -> Result<u8> {
    let mut result = serde_json::Map::new();
    result.insert("pkgscope_version".into(), env!("CARGO_PKG_VERSION").into());
    result.insert("os".into(), std::env::consts::OS.into());
    result.insert(
        "architecture".into(),
        crate::model::platform_architecture().into(),
    );
    result.insert(
        "terminal".into(),
        serde_json::json!({
            "stdin_tty": stdin().is_terminal(),
            "stdout_tty": stdout().is_terminal(),
            "no_color": std::env::var_os("NO_COLOR").is_some(),
            "size": crossterm::terminal::size().ok().map(|(width, height)| serde_json::json!({"width": width, "height": height}))
        }),
    );
    result.insert(
        "config".into(),
        serde_json::json!({"path": crate::config::config_path()?}),
    );
    let binary_path = std::env::current_exe().ok();
    let (signature_valid, developer_id_signed) = if std::env::consts::OS == "macos" {
        binary_path.as_ref().map_or((false, false), |path| {
            let path = path.to_str().unwrap_or_default();
            let verify = crate::process::CommandSpec::new(
                "/usr/bin/codesign",
                &["--verify", "--strict", path],
                Duration::from_secs(2),
            );
            let display = crate::process::CommandSpec::new(
                "/usr/bin/codesign",
                &["--display", "--verbose=4", path],
                Duration::from_secs(2),
            );
            let developer_id = crate::process::run(&display)
                .map(|output| {
                    output
                        .stderr_text()
                        .contains("Authority=Developer ID Application:")
                })
                .unwrap_or(false);
            (crate::process::run(&verify).is_ok(), developer_id)
        })
    } else {
        (false, false)
    };
    result.insert(
        "binary".into(),
        serde_json::json!({
            "path": binary_path,
            "code_signature_valid": signature_valid,
            "developer_id_signed": developer_id_signed
        }),
    );
    match StateStore::open_default_with_policy(
        config.storage.max_snapshots,
        config.storage.max_age_days,
    ) {
        Ok(store) => {
            result.insert(
                "state".into(),
                serde_json::json!({
                    "path": store.path(),
                    "health": store.health()?,
                    "max_snapshots": config.storage.max_snapshots,
                    "max_age_days": config.storage.max_age_days,
                    "permissions": state_permissions(store.path())
                }),
            );
        }
        Err(error) => {
            result.insert(
                "state".into(),
                serde_json::json!({"error": error.to_string()}),
            );
        }
    }
    let managers: Vec<_> = ManagerKind::ALL
        .into_iter()
        .map(|manager| {
            let executables = manager
                .executable_names()
                .iter()
                .flat_map(|name| crate::process::find_executables(name))
                .collect::<std::collections::BTreeSet<_>>();
            serde_json::json!({
                "manager": manager,
                "executables": executables,
                "available": !executables.is_empty()
            })
        })
        .collect();
    result.insert("managers".into(), managers.into());
    let duplicates = path_duplicates();
    result.insert(
        "path_duplicate_directories".into(),
        duplicates.clone().into(),
    );
    if common.format == OutputFormat::Json {
        output::json(&result)?;
    } else {
        println!("pkgscope doctor {}", env!("CARGO_PKG_VERSION"));
        println!(
            "  Platform: {} {}",
            std::env::consts::OS,
            crate::model::platform_architecture()
        );
        if let Some(state) = result.get("state") {
            println!("  State:    {state}");
        }
        println!(
            "  Signing:  {}",
            if std::env::consts::OS == "linux" {
                "unsigned Linux binary; verify SHA-256 and GitHub provenance"
            } else if signature_valid && developer_id_signed {
                "valid Developer ID signature"
            } else if signature_valid {
                "valid local/ad-hoc signature (not Developer ID)"
            } else {
                "not Developer ID verified (expected for local development builds)"
            }
        );
        println!("  Managers:");
        for manager in ManagerKind::ALL {
            let paths = manager
                .executable_names()
                .iter()
                .flat_map(|name| crate::process::find_executables(name))
                .collect::<std::collections::BTreeSet<_>>();
            if paths.is_empty() {
                println!("    {manager:<6} not found (normal if unused)");
            } else {
                println!(
                    "    {:<6} {}",
                    manager,
                    paths
                        .iter()
                        .map(|path| { crate::sanitize::terminal_text(&path.display().to_string()) })
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        if !duplicates.is_empty() {
            println!(
                "  PATH contains duplicate directories: {}",
                duplicates.join(", ")
            );
        }
    }
    Ok(0)
}

#[cfg(unix)]
fn state_permissions(path: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|metadata| format!("{:03o}", metadata.permissions().mode() & 0o777))
}

#[cfg(not(unix))]
fn state_permissions(_path: &std::path::Path) -> Option<String> {
    None
}

fn path_duplicates() -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();
    for path in std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default()
    {
        let path = crate::sanitize::terminal_text(&path.display().to_string());
        if !seen.insert(path.clone()) {
            duplicates.insert(path);
        }
    }
    duplicates.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parser_is_predictable() {
        assert_eq!(
            crate::config::parse_duration("500ms").unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            crate::config::parse_duration("10s").unwrap(),
            Duration::from_secs(10)
        );
        assert!(crate::config::parse_duration("0s").is_err());
    }

    #[test]
    fn schema_v1_snapshots_are_never_reused_by_v03() {
        let mut snapshot = Snapshot::empty(crate::model::ScanScope::default());
        snapshot.schema_version = 1;
        let common = CommonOptions {
            manager: Vec::new(),
            environment: Vec::new(),
            all_environments: false,
            refresh: false,
            offline: false,
            timeout: None,
            history: false,
            project_root: Vec::new(),
            format: OutputFormat::Json,
            color: None,
            quiet: true,
            verbose: false,
        };
        assert!(!cache_matches_request(&snapshot, &common));
        snapshot.schema_version = crate::model::SCHEMA_VERSION;
        assert!(cache_matches_request(&snapshot, &common));
    }
}
