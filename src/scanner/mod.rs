mod brew;
mod cargo;
mod npm;
mod pipx;
mod pnpm;
mod uv;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use chrono::{DateTime, Utc};

use crate::{
    analysis,
    model::{
        Category, CommandExposure, Confidence, EnvironmentMode, ExposureState, FieldValue,
        InstallIntent, InstallType, InstallationDates, InstallationPaths, InstallationRecord,
        InstallationSizes, ManagerInstance, ManagerKind, PackageIdentity, ScanError, ScanScope,
        ScanStatus, Snapshot, SourceKind, stable_id,
    },
    process,
    sanitize::terminal_text,
    size,
};

const MAX_CONCURRENT_SCANNERS: usize = 8;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub managers: Vec<ManagerKind>,
    pub all_environments: bool,
    pub timeout: Duration,
    pub calculate_sizes: bool,
    pub history: bool,
    pub project_roots: Vec<PathBuf>,
    pub verbose: bool,
    pub offline: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            managers: Vec::new(),
            all_environments: false,
            timeout: Duration::from_secs(10),
            calculate_sizes: true,
            history: false,
            project_roots: Vec::new(),
            verbose: false,
            offline: false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct PartialScan {
    pub instance: ManagerInstance,
    pub installations: Vec<InstallationRecord>,
    pub commands: Vec<CommandExposure>,
    pub errors: Vec<ScanError>,
}

impl PartialScan {
    fn failed(mut instance: ManagerInstance, code: &str, error: impl std::fmt::Display) -> Self {
        let message = terminal_text(&error.to_string());
        instance.scan_status = match code {
            "timeout" => ScanStatus::TimedOut,
            "parse_error" => ScanStatus::ParseError,
            "permission_denied" => ScanStatus::PermissionDenied,
            _ => ScanStatus::Failed,
        };
        Self {
            errors: vec![ScanError {
                manager: instance.manager,
                manager_instance_id: Some(instance.id.clone()),
                code: code.into(),
                message,
                recoverable: true,
                occurred_at: Utc::now(),
            }],
            instance,
            installations: Vec::new(),
            commands: Vec::new(),
        }
    }
}

pub fn scan(options: &ScanOptions) -> Snapshot {
    let requested: BTreeSet<_> = if options.managers.is_empty() {
        ManagerKind::ALL.into_iter().collect()
    } else {
        options.managers.iter().copied().collect()
    };
    let scope = ScanScope {
        user_scope: "current".into(),
        environment_mode: if options.all_environments {
            EnvironmentMode::Deep
        } else {
            EnvironmentMode::Active
        },
        history_enabled: options.history,
        project_roots: options
            .project_roots
            .iter()
            .map(|p| terminal_text(&p.display().to_string()))
            .collect(),
        requested_managers: options.managers.clone(),
    };
    let mut snapshot = Snapshot::empty(scope);
    let instances = discover_instances(&requested, options.all_environments);

    for batch in instances.chunks(MAX_CONCURRENT_SCANNERS) {
        if process::cancel_requested() {
            break;
        }
        let handles: Vec<_> = batch
            .iter()
            .cloned()
            .map(|instance| {
                let manager = instance.manager;
                let instance_id = instance.id.clone();
                let options = options.clone();
                (
                    manager,
                    instance_id,
                    thread::spawn(move || scan_instance(instance, &options)),
                )
            })
            .collect();
        for (manager, instance_id, handle) in handles {
            match handle.join() {
                Ok(partial) => {
                    snapshot.manager_instances.push(partial.instance);
                    snapshot.installations.extend(partial.installations);
                    snapshot.commands.extend(partial.commands);
                    snapshot.errors.extend(partial.errors);
                }
                Err(_) => snapshot.errors.push(ScanError {
                    manager,
                    manager_instance_id: Some(instance_id),
                    code: "scanner_panic".into(),
                    message: "A scanner worker stopped unexpectedly; other results were preserved."
                        .into(),
                    recoverable: true,
                    occurred_at: Utc::now(),
                }),
            }
        }
    }

    normalize_instances(&mut snapshot);

    snapshot
        .manager_instances
        .sort_by(|a, b| (a.manager, &a.executable_path).cmp(&(b.manager, &b.executable_path)));
    snapshot.installations.sort_by(|a, b| {
        (&a.identity.name, &a.environment, &a.id).cmp(&(&b.identity.name, &b.environment, &b.id))
    });
    snapshot.partial = !snapshot.errors.is_empty()
        || snapshot
            .manager_instances
            .iter()
            .any(|instance| instance.scan_status != ScanStatus::Success);
    analysis::apply_findings(&mut snapshot);
    snapshot
}

fn normalize_instances(snapshot: &mut Snapshot) {
    let mut groups: BTreeMap<String, Vec<ManagerInstance>> = BTreeMap::new();
    for mut instance in snapshot.manager_instances.drain(..) {
        instance.executable_path = terminal_text(&instance.executable_path);
        instance.root = instance.root.map(|root| terminal_text(&root));
        instance.runtime_manager = instance
            .runtime_manager
            .map(|manager| terminal_text(&manager));
        if let Some(runtime) = &mut instance.runtime {
            runtime.name = terminal_text(&runtime.name);
            runtime.version = runtime
                .version
                .take()
                .map(|version| terminal_text(&version));
            runtime.executable_path = runtime
                .executable_path
                .take()
                .map(|path| terminal_text(&path));
        }
        instance.discovered_by = instance
            .discovered_by
            .into_iter()
            .map(|value| terminal_text(&value))
            .collect();
        instance.capabilities = instance
            .capabilities
            .into_iter()
            .map(|value| terminal_text(&value))
            .collect();
        let root = instance.root.as_deref().unwrap_or("");
        let runtime = instance
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.executable_path.as_deref());
        let key = if matches!(instance.manager, ManagerKind::Npm | ManagerKind::Pnpm)
            && !root.is_empty()
            && runtime.is_some()
        {
            format!(
                "logical\0{}\0{}\0{}\0{}",
                instance.manager,
                root,
                runtime.unwrap_or_default(),
                instance.architecture
            )
        } else {
            format!(
                "executable\0{}\0{}\0{}\0{}",
                instance.manager, instance.executable_path, root, instance.architecture
            )
        };
        groups.entry(key).or_default().push(instance);
    }
    let mut instance_remap = BTreeMap::new();
    let mut normalized_instances = Vec::new();
    for (key, mut instances) in groups {
        instances.sort_by_key(|instance| {
            let manager_parent = Path::new(&instance.executable_path).parent();
            let runtime_parent = instance
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.executable_path.as_deref())
                .and_then(|path| Path::new(path).parent());
            (
                manager_parent != runtime_parent,
                instance.executable_path.clone(),
            )
        });
        let mut primary = instances.remove(0);
        let normalized_id = stable_id(&["manager_instance", &key]);
        instance_remap.insert(primary.id.clone(), normalized_id.clone());
        for alias in instances {
            instance_remap.insert(alias.id, normalized_id.clone());
            primary.discovered_by.extend(alias.discovered_by);
            primary.capabilities.extend(alias.capabilities);
        }
        primary.discovered_by.sort();
        primary.discovered_by.dedup();
        primary.capabilities.sort();
        primary.capabilities.dedup();
        primary.id = normalized_id;
        normalized_instances.push(primary);
    }
    snapshot.manager_instances = normalized_instances;
    let instance_environments: BTreeMap<_, _> = snapshot
        .manager_instances
        .iter()
        .map(|instance| (instance.id.clone(), environment_label(instance)))
        .collect();

    let mut installation_remap = BTreeMap::new();
    for record in &mut snapshot.installations {
        let old_id = record.id.clone();
        if let Some(instance_id) = instance_remap.get(&record.manager_instance_id) {
            record.manager_instance_id = instance_id.clone();
        }
        if let Some(environment) = instance_environments.get(&record.manager_instance_id) {
            record.environment = environment.clone();
        }
        record.id = stable_id(&[
            &record.manager_instance_id,
            &record.identity.ecosystem,
            &record.identity.name,
            record.paths.install_root.as_deref().unwrap_or(""),
            record.architecture.value.as_deref().unwrap_or("unknown"),
            &format!("{:?}", record.identity.source_kind),
        ]);
        installation_remap.insert(old_id, record.id.clone());
    }
    let mut unique_installations = BTreeMap::new();
    for record in snapshot.installations.drain(..) {
        unique_installations
            .entry(record.id.clone())
            .or_insert(record);
    }
    snapshot.installations = unique_installations.into_values().collect();

    for command in &mut snapshot.commands {
        if let Some(owner) = installation_remap.get(&command.owner_installation_id) {
            command.owner_installation_id = owner.clone();
        }
        command.id = stable_id(&[&command.owner_installation_id, &command.name, &command.path]);
    }
    let mut unique_commands = BTreeMap::new();
    for command in snapshot.commands.drain(..) {
        unique_commands.entry(command.id.clone()).or_insert(command);
    }
    snapshot.commands = unique_commands.into_values().collect();
    for record in &mut snapshot.installations {
        record.command_ids = snapshot
            .commands
            .iter()
            .filter(|command| command.owner_installation_id == record.id)
            .map(|command| command.id.clone())
            .collect();
    }
    for error in &mut snapshot.errors {
        if let Some(instance_id) = &error.manager_instance_id
            && let Some(normalized) = instance_remap.get(instance_id)
        {
            error.manager_instance_id = Some(normalized.clone());
        }
    }
}

fn discover_instances(
    requested: &BTreeSet<ManagerKind>,
    all_environments: bool,
) -> Vec<ManagerInstance> {
    let mut discovered = Vec::new();
    for manager in requested {
        let mut paths = process::find_executables(manager.executable());
        if *manager == ManagerKind::Brew {
            for path in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] {
                let path = PathBuf::from(path);
                if process::is_executable(&path) && !paths.contains(&path) {
                    paths.push(path);
                }
            }
        }
        if all_environments {
            paths.extend(deep_instance_candidates(*manager));
        }
        let mut unique = BTreeSet::new();
        for path in paths {
            let key_path = path.canonicalize().unwrap_or_else(|_| path.clone());
            let key = format!("{}:{}", manager, key_path.display());
            if !unique.insert(key) {
                continue;
            }
            let display_path = terminal_text(&path.display().to_string());
            let id = stable_id(&[&manager.to_string(), &display_path]);
            let discovered_by = if path.as_path() == Path::new("/opt/homebrew/bin/brew")
                || path.as_path() == Path::new("/usr/local/bin/brew")
            {
                vec!["standard_prefix".into()]
            } else if all_environments && !path_in_current_path(&path) {
                vec!["deep_scan".into()]
            } else {
                vec!["PATH".into()]
            };
            discovered.push(ManagerInstance {
                id,
                manager: *manager,
                executable_path: display_path,
                root: None,
                runtime: None,
                runtime_manager: detect_runtime_manager(&path),
                architecture: detect_architecture(*manager, &path),
                scope_owner: "current_user".into(),
                discovered_by,
                scan_status: ScanStatus::Success,
                scanned_at: Utc::now(),
                capabilities: vec!["list".into(), "commands".into(), "removal_plan".into()],
            });
        }
    }
    discovered
}

fn deep_instance_candidates(manager: ManagerKind) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let Some(home) = dirs::home_dir() else {
        return candidates;
    };
    let relative_patterns: &[&str] = match manager {
        ManagerKind::Npm => &[".volta/bin/npm", ".local/share/mise/shims/npm"],
        ManagerKind::Pnpm => &[".volta/bin/pnpm", ".local/share/pnpm/pnpm"],
        ManagerKind::Pipx => &[".local/bin/pipx"],
        ManagerKind::Uv => &[".local/bin/uv"],
        ManagerKind::Cargo => &[".cargo/bin/cargo"],
        ManagerKind::Brew => &[],
    };
    for relative in relative_patterns {
        let candidate = home.join(relative);
        if process::is_executable(&candidate) {
            candidates.push(candidate);
        }
    }
    if matches!(manager, ManagerKind::Npm | ManagerKind::Pnpm) {
        let executable = manager.executable();
        for base in [
            home.join(".nvm/versions/node"),
            home.join(".fnm/node-versions"),
            home.join(".local/share/mise/installs/node"),
            home.join(".volta/tools/image/node"),
        ] {
            if !base.is_dir() {
                continue;
            }
            for entry in walkdir::WalkDir::new(base)
                .max_depth(5)
                .follow_links(false)
                .into_iter()
                .flatten()
                .take(10_000)
            {
                if entry.file_name() == executable && process::is_executable(entry.path()) {
                    candidates.push(entry.into_path());
                    if candidates.len() >= 128 {
                        return candidates;
                    }
                }
            }
        }
    }
    candidates
}

fn path_in_current_path(path: &Path) -> bool {
    process::find_executables(
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or_default(),
    )
    .iter()
    .any(|candidate| candidate == path)
}

fn detect_runtime_manager(path: &Path) -> Option<String> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    ["volta", "nvm", "fnm", "mise", "asdf", "pyenv", "homebrew"]
        .into_iter()
        .find(|name| lower.contains(name))
        .map(str::to_string)
}

fn detect_architecture(manager: ManagerKind, path: &Path) -> String {
    let path = path.to_string_lossy();
    if manager == ManagerKind::Brew && path.starts_with("/usr/local/") {
        "x86_64".into()
    } else if manager == ManagerKind::Brew && path.starts_with("/opt/homebrew/") {
        "arm64".into()
    } else {
        executable_architecture(Path::new(path.as_ref()), 0).unwrap_or_else(|| "unknown".into())
    }
}

fn executable_architecture(path: &Path, depth: usize) -> Option<String> {
    if depth > 2 {
        return None;
    }
    if let Some(architecture) = mach_o_architecture(path) {
        return Some(architecture);
    }
    let bytes = read_prefix(path, 512)?;
    let first_line = std::str::from_utf8(&bytes[..bytes.len().min(512)])
        .ok()?
        .lines()
        .next()?;
    let shebang = first_line.strip_prefix("#!")?.trim();
    let mut parts = shebang.split_whitespace();
    let interpreter = parts.next()?;
    let interpreter_path = if interpreter == "/usr/bin/env" {
        let name = parts.find(|part| !part.starts_with('-'))?;
        path.parent()
            .map(|parent| parent.join(name))
            .filter(|candidate| process::is_executable(candidate))
            .or_else(|| process::find_executables(name).into_iter().next())?
    } else {
        PathBuf::from(interpreter)
    };
    executable_architecture(&interpreter_path, depth + 1)
}

fn mach_o_architecture(path: &Path) -> Option<String> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let bytes = read_prefix(&path, 2048)?;
    if bytes.len() < 8 {
        return None;
    }
    let magic_be = u32::from_be_bytes(bytes[0..4].try_into().ok()?);
    let magic_le = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    const MH_MAGIC: u32 = 0xfeedface;
    const MH_MAGIC_64: u32 = 0xfeedfacf;
    const FAT_MAGIC: u32 = 0xcafebabe;
    const FAT_MAGIC_64: u32 = 0xcafebabf;
    if matches!(magic_le, MH_MAGIC | MH_MAGIC_64) {
        return cpu_architecture(u32::from_le_bytes(bytes[4..8].try_into().ok()?));
    }
    if matches!(magic_be, MH_MAGIC | MH_MAGIC_64) {
        return cpu_architecture(u32::from_be_bytes(bytes[4..8].try_into().ok()?));
    }
    let (entry_size, count) = if magic_be == FAT_MAGIC {
        (
            20,
            u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize,
        )
    } else if magic_be == FAT_MAGIC_64 {
        (
            32,
            u32::from_be_bytes(bytes[4..8].try_into().ok()?) as usize,
        )
    } else {
        return None;
    };
    let mut architectures = BTreeSet::new();
    for index in 0..count.min(32) {
        let offset = 8 + index * entry_size;
        if offset + 4 > bytes.len() {
            break;
        }
        if let Some(architecture) = cpu_architecture(u32::from_be_bytes(
            bytes[offset..offset + 4].try_into().ok()?,
        )) {
            architectures.insert(architecture);
        }
    }
    match architectures.len() {
        0 => None,
        1 => architectures.into_iter().next(),
        _ => Some("universal".into()),
    }
}

fn read_prefix(path: &Path, limit: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let mut bytes = vec![0_u8; limit];
    let count = file.read(&mut bytes).ok()?;
    bytes.truncate(count);
    Some(bytes)
}

fn cpu_architecture(cpu_type: u32) -> Option<String> {
    match cpu_type {
        0x0100_000c => Some("arm64".into()),
        0x0100_0007 => Some("x86_64".into()),
        _ => None,
    }
}

fn scan_instance(instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    match instance.manager {
        ManagerKind::Brew => brew::scan(instance, options),
        ManagerKind::Npm => npm::scan(instance, options),
        ManagerKind::Pnpm => pnpm::scan(instance, options),
        ManagerKind::Pipx => pipx::scan(instance, options),
        ManagerKind::Uv => uv::scan(instance, options),
        ManagerKind::Cargo => cargo::scan(instance, options),
    }
}

pub(crate) fn command(
    instance: &ManagerInstance,
    args: &[&str],
    options: &ScanOptions,
) -> Result<process::CommandOutput, process::CommandError> {
    process::run(&manager_command_spec(instance, args, options))
}

pub(crate) fn manager_command_spec(
    instance: &ManagerInstance,
    args: &[&str],
    options: &ScanOptions,
) -> process::CommandSpec {
    let mut spec = process::CommandSpec::new(&instance.executable_path, args, options.timeout);
    spec.env.insert("NO_COLOR".into(), "1".into());
    spec.env.insert("CLICOLOR".into(), "0".into());
    for name in [
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "SHELL",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "HOMEBREW_PREFIX",
        "HOMEBREW_CELLAR",
        "NPM_CONFIG_PREFIX",
        "npm_config_prefix",
        "NODE_PATH",
        "VOLTA_HOME",
        "NVM_BIN",
        "NVM_DIR",
        "PNPM_HOME",
        "PIPX_HOME",
        "PIPX_BIN_DIR",
        "PIPX_DEFAULT_PYTHON",
        "UV_TOOL_DIR",
        "UV_TOOL_BIN_DIR",
        "CARGO_HOME",
        "CARGO_INSTALL_ROOT",
        "RUSTUP_HOME",
    ] {
        if let Ok(value) = std::env::var(name) {
            spec.env.insert(name.into(), value);
        }
    }
    if let Some(parent) = Path::new(&instance.executable_path).parent() {
        let current_path = spec.env.get("PATH").cloned().unwrap_or_default();
        let mut paths = vec![parent.to_path_buf()];
        paths.extend(std::env::split_paths(std::ffi::OsStr::new(&current_path)));
        if let Ok(path) = std::env::join_paths(paths) {
            spec.env
                .insert("PATH".into(), path.to_string_lossy().into_owned());
        }
        if instance.runtime_manager.as_deref() == Some("nvm") {
            spec.env
                .insert("NVM_BIN".into(), parent.to_string_lossy().into_owned());
        }
    }
    if instance.manager == ManagerKind::Brew {
        spec.env
            .insert("HOMEBREW_NO_AUTO_UPDATE".into(), "1".into());
        spec.env
            .insert("HOMEBREW_NO_INSTALL_CLEANUP".into(), "1".into());
        spec.env.insert("HOMEBREW_NO_ANALYTICS".into(), "1".into());
    }
    if instance.manager == ManagerKind::Npm {
        spec.env.insert("NO_UPDATE_NOTIFIER".into(), "1".into());
        spec.env
            .insert("NPM_CONFIG_UPDATE_NOTIFIER".into(), "false".into());
        spec.env.insert("NPM_CONFIG_AUDIT".into(), "false".into());
        spec.env.insert("NPM_CONFIG_FUND".into(), "false".into());
    }
    if instance.manager == ManagerKind::Pipx {
        spec.env
            .insert("PIPX_DISABLE_SHARED_LIBS_AUTO_UPGRADE".into(), "1".into());
    }
    if options.offline {
        spec.env.insert("NPM_CONFIG_OFFLINE".into(), "true".into());
        spec.env.insert("UV_OFFLINE".into(), "1".into());
    }
    if options.verbose {
        spec.env
            .insert("PKGSCOPE_SCANNER_VERBOSE".into(), "1".into());
    }
    spec
}

pub(crate) fn command_error_code(error: &process::CommandError) -> &'static str {
    match error {
        process::CommandError::TimedOut(_) => "timeout",
        process::CommandError::Cancelled => "cancelled",
        process::CommandError::Spawn { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            "permission_denied"
        }
        process::CommandError::OutputLimit { .. } => "output_limit",
        _ => "command_failed",
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_record(
    instance: &ManagerInstance,
    name: &str,
    version: Option<&str>,
    ecosystem: &str,
    source_kind: SourceKind,
    source_ref: Option<String>,
    root: Option<PathBuf>,
    bin_paths: Vec<PathBuf>,
    category: Category,
    install_type: InstallType,
    intent: InstallIntent,
    options: &ScanOptions,
) -> (InstallationRecord, Vec<CommandExposure>) {
    let name = terminal_text(name);
    let source_ref = source_ref.map(|value| terminal_text(&value));
    let root_display = root
        .as_ref()
        .map(|path| terminal_text(&path.display().to_string()));
    let id = stable_id(&[
        &instance.id,
        ecosystem,
        &name,
        root_display.as_deref().unwrap_or(""),
        &instance.architecture,
        &format!("{source_kind:?}"),
    ]);
    let observed = Utc::now();
    let mut paths = InstallationPaths {
        install_root: root_display,
        bins: bin_paths
            .iter()
            .map(|path| terminal_text(&path.display().to_string()))
            .collect(),
        ..Default::default()
    };
    paths.bins.sort();
    paths.bins.dedup();

    let filesystem_created_at = root.as_ref().and_then(|root| {
        fs::metadata(root)
            .and_then(|metadata| metadata.created())
            .ok()
            .map(|created| FieldValue {
                value: Some(DateTime::<Utc>::from(created)),
                source: "filesystem_birthtime".into(),
                confidence: Confidence::Estimated,
                observed_at: observed,
            })
    });
    let sizes = if options.calculate_sizes {
        root.as_ref()
            .filter(|path| path.exists())
            .map_or_else(InstallationSizes::default, |root| {
                let measurement = size::measure_owned(root, 250_000);
                InstallationSizes {
                    owned_apparent_bytes: Some(measurement.apparent_bytes),
                    owned_allocated_bytes: Some(measurement.allocated_bytes),
                    shared_store_bytes: None,
                    dedicated_cache_bytes: None,
                    estimated_reclaimable_bytes: if source_kind == SourceKind::Linked {
                        None
                    } else {
                        Some(measurement.allocated_bytes)
                    },
                    confidence: if measurement.incomplete {
                        Confidence::Estimated
                    } else if source_kind == SourceKind::Linked {
                        Confidence::Ambiguous
                    } else {
                        Confidence::High
                    },
                    method: if measurement.incomplete {
                        "bounded_filesystem_walk_incomplete".into()
                    } else {
                        "filesystem_walk_no_symlink_follow_inode_dedup".into()
                    },
                }
            })
    } else {
        InstallationSizes::default()
    };

    let mut commands = Vec::new();
    for bin in bin_paths {
        let command_name = bin
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown");
        let command_name = terminal_text(command_name);
        let path = terminal_text(&bin.display().to_string());
        let command_id = stable_id(&[&id, &command_name, &path]);
        let real_path = bin
            .canonicalize()
            .ok()
            .map(|path| terminal_text(&path.display().to_string()));
        let broken =
            fs::symlink_metadata(&bin).is_err() || (bin.is_file() && !process::is_executable(&bin));
        commands.push(CommandExposure {
            id: command_id,
            name: command_name,
            path,
            real_path,
            owner_installation_id: id.clone(),
            path_rank: None,
            on_current_path: false,
            exposure_state: if broken {
                ExposureState::Broken
            } else {
                ExposureState::Hidden
            },
            shell_resolution: None,
        });
    }
    let command_ids = commands.iter().map(|c| c.id.clone()).collect();
    (
        InstallationRecord {
            id,
            identity: PackageIdentity {
                ecosystem: ecosystem.into(),
                name,
                source_kind,
                source_ref,
            },
            manager_instance_id: instance.id.clone(),
            category,
            version: version.map_or_else(
                || FieldValue::unknown("manager_output"),
                |value| FieldValue::exact(terminal_text(value), "manager_output"),
            ),
            architecture: if instance.architecture == "unknown" {
                FieldValue::unknown("manager_executable_architecture")
            } else {
                FieldValue::exact(
                    instance.architecture.clone(),
                    "manager_executable_architecture",
                )
            },
            install_type,
            intent,
            environment: environment_label(instance),
            paths,
            dates: InstallationDates {
                filesystem_created_at,
                ..Default::default()
            },
            sizes,
            command_ids,
            finding_ids: Vec::new(),
            removal_plan_available: true,
            metadata: BTreeMap::new(),
        },
        commands,
    )
}

pub(crate) fn environment_label(instance: &ManagerInstance) -> String {
    if instance.manager == ManagerKind::Brew {
        return instance.architecture.clone();
    }
    if matches!(
        instance.manager,
        ManagerKind::Pipx | ManagerKind::Uv | ManagerKind::Cargo
    ) {
        return "default".into();
    }
    if let Some(manager) = &instance.runtime_manager {
        return terminal_text(&instance.runtime.as_ref().map_or_else(
            || manager.clone(),
            |runtime| {
                runtime.version.as_deref().map_or_else(
                    || format!("{manager}:{}", runtime.name),
                    |version| {
                        format!(
                            "{manager}:{}@{}",
                            runtime.name,
                            version.trim_start_matches('v')
                        )
                    },
                )
            },
        ));
    }
    if let Some(runtime) = &instance.runtime {
        return terminal_text(&runtime.version.as_deref().map_or_else(
            || runtime.name.clone(),
            |version| format!("{}@{}", runtime.name, version.trim_start_matches('v')),
        ));
    }
    instance
        .root
        .as_deref()
        .and_then(|root| Path::new(root).file_name())
        .and_then(|name| name.to_str())
        .map(terminal_text)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "default".into())
}

pub(crate) fn package_json_bin_names(root: &Path) -> Vec<String> {
    let package_json = root.join("package.json");
    let Ok(bytes) = read_file_bounded(&package_json, 2 * 1024 * 1024) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Vec::new();
    };
    match value.get("bin") {
        Some(serde_json::Value::String(path)) => value
            .get("name")
            .and_then(|name| name.as_str())
            .map(|name| vec![(name.to_string(), path.to_string())])
            .unwrap_or_default(),
        Some(serde_json::Value::Object(bins)) => bins
            .iter()
            .filter_map(|(name, path)| path.as_str().map(|path| (name.clone(), path.to_string())))
            .collect(),
        _ => Vec::new(),
    }
    .into_iter()
    .map(|(name, _)| terminal_text(&name))
    .collect()
}

pub(crate) fn enrich_from_package_json(record: &mut InstallationRecord, root: &Path) {
    let Ok(bytes) = read_file_bounded(&root.join("package.json"), 2 * 1024 * 1024) else {
        return;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return;
    };
    insert_metadata_text(
        record,
        "description",
        value.get("description").and_then(|v| v.as_str()),
    );
    if record.metadata.contains_key("description") {
        record
            .metadata
            .insert("description_source".into(), "installed_package_json".into());
    }
    insert_metadata_text(
        record,
        "homepage",
        json_string_or_first(value.get("homepage")),
    );
    let repository = value.get("repository").and_then(|repository| {
        repository
            .as_str()
            .or_else(|| repository.get("url").and_then(|url| url.as_str()))
    });
    insert_metadata_text(record, "repository", repository);
    insert_metadata_text(
        record,
        "license",
        json_string_or_first(value.get("license")),
    );
}

pub(crate) fn enrich_from_python_metadata(
    record: &mut InstallationRecord,
    root: &Path,
    package_name: &str,
) {
    for entry in walkdir::WalkDir::new(root)
        .max_depth(6)
        .follow_links(false)
        .into_iter()
        .flatten()
        .take(250_000)
    {
        if entry.file_name() != "METADATA" {
            continue;
        }
        let Some(parent) = entry.path().parent().and_then(Path::file_name) else {
            continue;
        };
        if !parent.to_string_lossy().ends_with(".dist-info") {
            continue;
        }
        let Ok(content) = read_text_bounded(entry.path(), 2 * 1024 * 1024) else {
            continue;
        };
        let Some(name) = metadata_header(&content, "Name") else {
            continue;
        };
        if normalize_package_name(&name) != normalize_package_name(package_name) {
            continue;
        }
        insert_metadata_text(
            record,
            "description",
            metadata_header(&content, "Summary").as_deref(),
        );
        if record.metadata.contains_key("description") {
            record.metadata.insert(
                "description_source".into(),
                "installed_dist_info_metadata".into(),
            );
        }
        let homepage = metadata_header(&content, "Home-page").or_else(|| {
            content.lines().find_map(|line| {
                let value = line.strip_prefix("Project-URL: ")?;
                let (label, url) = value.split_once(',')?;
                matches!(
                    label.trim().to_ascii_lowercase().as_str(),
                    "homepage" | "home"
                )
                .then(|| url.trim().to_string())
            })
        });
        insert_metadata_text(record, "homepage", homepage.as_deref());
        let license = metadata_header(&content, "License-Expression")
            .or_else(|| metadata_header(&content, "License"));
        insert_metadata_text(record, "license", license.as_deref());
        return;
    }
}

pub(crate) fn insert_metadata_text(
    record: &mut InstallationRecord,
    key: &str,
    value: Option<&str>,
) {
    let Some(value) = value else {
        return;
    };
    let value = terminal_text(value.trim());
    if value.is_empty() {
        return;
    }
    let value = value.chars().take(4096).collect::<String>();
    record.metadata.insert(key.into(), value.into());
}

fn json_string_or_first(value: Option<&serde_json::Value>) -> Option<&str> {
    match value {
        Some(serde_json::Value::String(value)) => Some(value),
        Some(serde_json::Value::Array(values)) => values.first().and_then(|value| value.as_str()),
        _ => None,
    }
}

fn metadata_header(content: &str, name: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .map(terminal_text)
}

fn normalize_package_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if matches!(ch, '-' | '_' | '.') {
                '-'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect()
}

pub(crate) fn read_file_bounded(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    fs::File::open(path)?
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds the {limit} byte safety limit", path.display()),
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_text_bounded(path: &Path, limit: usize) -> std::io::Result<String> {
    String::from_utf8(read_file_bounded(path, limit)?).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is not valid UTF-8: {error}", path.display()),
        )
    })
}

pub(crate) fn bins_in_directory(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            fs::symlink_metadata(path)
                .map(|metadata| metadata.file_type().is_symlink() || process::is_executable(path))
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_instance(id: &str, executable: &Path) -> ManagerInstance {
        ManagerInstance {
            id: id.into(),
            manager: ManagerKind::Npm,
            executable_path: executable.display().to_string(),
            root: Some("/shared/node_modules".into()),
            runtime: None,
            runtime_manager: None,
            architecture: "arm64".into(),
            scope_owner: "current_user".into(),
            discovered_by: vec!["test".into()],
            scan_status: ScanStatus::Success,
            scanned_at: Utc::now(),
            capabilities: vec!["list".into()],
        }
    }

    #[test]
    fn reads_thin_and_universal_mach_o_architectures() {
        let temp = tempfile::tempdir().unwrap();
        let thin = temp.path().join("thin");
        let mut thin_bytes = Vec::new();
        thin_bytes.extend_from_slice(&0xfeedfacf_u32.to_le_bytes());
        thin_bytes.extend_from_slice(&0x0100000c_u32.to_le_bytes());
        fs::write(&thin, thin_bytes).unwrap();
        assert_eq!(mach_o_architecture(&thin).as_deref(), Some("arm64"));

        let universal = temp.path().join("universal");
        let mut fat_bytes = Vec::new();
        fat_bytes.extend_from_slice(&0xcafebabe_u32.to_be_bytes());
        fat_bytes.extend_from_slice(&2_u32.to_be_bytes());
        for cpu in [0x0100000c_u32, 0x01000007_u32] {
            fat_bytes.extend_from_slice(&cpu.to_be_bytes());
            fat_bytes.extend_from_slice(&[0_u8; 16]);
        }
        fs::write(&universal, fat_bytes).unwrap();
        assert_eq!(
            mach_o_architecture(&universal).as_deref(),
            Some("universal")
        );
    }

    #[test]
    fn preserves_records_from_distinct_manager_instances() {
        let first = test_instance("first", Path::new("/one/npm"));
        let second = test_instance("second", Path::new("/two/npm"));
        let options = ScanOptions {
            calculate_sizes: false,
            ..ScanOptions::default()
        };
        let (first_record, _) = make_record(
            &first,
            "tool",
            Some("1.0.0"),
            "npm",
            SourceKind::Registry,
            None,
            Some(PathBuf::from("/shared/node_modules/tool")),
            Vec::new(),
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            &options,
        );
        let (second_record, _) = make_record(
            &second,
            "tool",
            Some("1.0.0"),
            "npm",
            SourceKind::Registry,
            None,
            Some(PathBuf::from("/shared/node_modules/tool")),
            Vec::new(),
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            &options,
        );
        let mut snapshot = Snapshot::empty(ScanScope::default());
        snapshot.manager_instances = vec![first, second];
        snapshot.installations = vec![first_record, second_record];

        normalize_instances(&mut snapshot);

        assert_eq!(snapshot.manager_instances.len(), 2);
        assert_eq!(snapshot.installations.len(), 2);
        assert_ne!(snapshot.installations[0].id, snapshot.installations[1].id);
    }

    #[test]
    fn installation_id_does_not_change_with_version() {
        let instance = test_instance("stable", Path::new("/manager/npm"));
        let options = ScanOptions {
            calculate_sizes: false,
            ..ScanOptions::default()
        };
        let record = |version| {
            make_record(
                &instance,
                "tool",
                Some(version),
                "npm",
                SourceKind::Registry,
                None,
                Some(PathBuf::from("/shared/node_modules/tool")),
                Vec::new(),
                Category::Cli,
                InstallType::Normal,
                InstallIntent::Explicit,
                &options,
            )
            .0
        };

        assert_eq!(record("1.0.0").id, record("2.0.0").id);
    }

    #[test]
    fn merges_manager_aliases_for_the_same_root_and_runtime() {
        let mut alias = test_instance("alias", Path::new("/alias/npm"));
        let mut paired = test_instance("paired", Path::new("/runtime/npm"));
        paired.runtime_manager = Some("nvm".into());
        for instance in [&mut alias, &mut paired] {
            instance.runtime = Some(crate::model::RuntimeInfo {
                name: "node".into(),
                version: Some("v22.0.0".into()),
                executable_path: Some("/runtime/node".into()),
            });
        }
        let options = ScanOptions {
            calculate_sizes: false,
            ..ScanOptions::default()
        };
        let (alias_record, _) = make_record(
            &alias,
            "tool",
            Some("1.0.0"),
            "npm",
            SourceKind::Registry,
            None,
            Some(PathBuf::from("/shared/node_modules/tool")),
            Vec::new(),
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            &options,
        );
        let (paired_record, _) = make_record(
            &paired,
            "tool",
            Some("1.0.0"),
            "npm",
            SourceKind::Registry,
            None,
            Some(PathBuf::from("/shared/node_modules/tool")),
            Vec::new(),
            Category::Cli,
            InstallType::Normal,
            InstallIntent::Explicit,
            &options,
        );
        let mut snapshot = Snapshot::empty(ScanScope::default());
        snapshot.manager_instances = vec![alias, paired];
        snapshot.installations = vec![alias_record, paired_record];

        normalize_instances(&mut snapshot);

        assert_eq!(snapshot.manager_instances.len(), 1);
        assert_eq!(
            snapshot.manager_instances[0].executable_path,
            "/runtime/npm"
        );
        assert_eq!(snapshot.installations.len(), 1);
        assert_eq!(snapshot.installations[0].environment, "nvm:node@22.0.0");
    }

    #[test]
    fn manager_command_prefers_the_runtime_beside_the_manager() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let manager = temp.path().join("npm");
        let runtime = temp.path().join("paired-runtime");
        fs::write(&manager, "#!/usr/bin/env paired-runtime\n").unwrap();
        fs::write(&runtime, "#!/bin/sh\nprintf paired\n").unwrap();
        for path in [&manager, &runtime] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }
        let mut instance = test_instance("paired", &manager);
        instance.root = None;

        let output = command(&instance, &[], &ScanOptions::default()).unwrap();

        assert_eq!(output.stdout_text(), "paired");
    }
}
