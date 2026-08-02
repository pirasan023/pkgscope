use std::{collections::BTreeSet, path::Path, time::Duration};

use anyhow::{Context, Result, bail};

use crate::{
    cli::build_removal_plan,
    model::{InstallationRecord, ManagerInstance, ManagerKind, RemovalPlan, ScanStatus, Snapshot},
    process::{self, CommandOutput},
    scanner::{self, ScanOptions},
};

#[derive(Debug)]
pub(crate) struct VerifiedRemoval {
    pub plan: RemovalPlan,
    pub instance: ManagerInstance,
}

pub(crate) fn revalidate(
    expected_record: &InstallationRecord,
    expected_plan: &RemovalPlan,
    fresh: &Snapshot,
) -> Result<VerifiedRemoval> {
    let current_executable = std::env::current_exe().context("could not identify pkgscope")?;
    revalidate_with_executable(expected_record, expected_plan, fresh, &current_executable)
}

fn revalidate_with_executable(
    expected_record: &InstallationRecord,
    expected_plan: &RemovalPlan,
    fresh: &Snapshot,
    current_executable: &Path,
) -> Result<VerifiedRemoval> {
    let record = fresh
        .installations
        .iter()
        .find(|record| record.id == expected_record.id)
        .context("the selected installation is no longer present; nothing was executed")?;
    if record.manager_instance_id != expected_record.manager_instance_id
        || record.identity != expected_record.identity
        || record.version.value != expected_record.version.value
        || record.paths.install_root != expected_record.paths.install_root
    {
        bail!("the selected installation changed since confirmation; nothing was executed");
    }
    let instance = fresh
        .manager_instances
        .iter()
        .find(|instance| instance.id == record.manager_instance_id)
        .context("the owning manager instance is no longer available")?;
    if instance.scan_status != ScanStatus::Success {
        bail!("the owning manager could not be revalidated successfully");
    }
    if !process::is_executable(Path::new(&instance.executable_path)) {
        bail!("the owning manager executable is no longer executable");
    }

    let fresh_plan = build_removal_plan(fresh, record)?;
    if fresh_plan.manager_instance_id != expected_plan.manager_instance_id
        || fresh_plan.target_name != expected_plan.target_name
        || fresh_plan.target_version != expected_plan.target_version
        || fresh_plan.action.executable != expected_plan.action.executable
        || fresh_plan.action.argv != expected_plan.action.argv
        || fresh_plan.action.cwd != expected_plan.action.cwd
        || fresh_plan.action.env_overrides != expected_plan.action.env_overrides
    {
        bail!("the manager action changed since confirmation; nothing was executed");
    }
    if !fresh_plan.managed_dependents.is_empty() {
        bail!(
            "managed dependents still require this package: {}",
            fresh_plan.managed_dependents.join(", ")
        );
    }
    if record.identity.name == "pkgscope" || owns_path(fresh, record, current_executable) {
        bail!("pkgscope refuses to uninstall the currently running pkgscope installation");
    }
    if owns_path(fresh, record, Path::new(&instance.executable_path)) {
        bail!("pkgscope refuses to remove the package manager needed for this action");
    }
    if let Some(runtime) = &instance.runtime
        && let Some(executable) = &runtime.executable_path
        && owns_path(fresh, record, Path::new(executable))
    {
        bail!("pkgscope refuses to remove the runtime needed for this action");
    }
    require_privileges(record, &fresh_plan)?;
    verify_system_removal_transaction(instance, record, &fresh_plan)?;

    Ok(VerifiedRemoval {
        plan: fresh_plan,
        instance: instance.clone(),
    })
}

fn owns_path(snapshot: &Snapshot, record: &InstallationRecord, target: &Path) -> bool {
    record
        .paths
        .bins
        .iter()
        .map(Path::new)
        .chain(
            snapshot
                .commands
                .iter()
                .filter(|command| command.owner_installation_id == record.id)
                .flat_map(|command| {
                    [Some(command.path.as_str()), command.real_path.as_deref()]
                        .into_iter()
                        .flatten()
                        .map(Path::new)
                }),
        )
        .any(|owned| same_path(owned, target))
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub(crate) fn execute(verified: &VerifiedRemoval, options: &ScanOptions) -> Result<CommandOutput> {
    let record_requires_root = verified
        .plan
        .preconditions
        .iter()
        .any(|precondition| precondition == "already_running_with_root_privileges");
    if record_requires_root && !has_root_privileges() {
        bail!(
            "root privileges are required; pkgscope never starts sudo automatically. Run the displayed command from an already-authorized root session"
        );
    }
    let args = verified
        .plan
        .action
        .argv
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut spec = scanner::manager_command_spec(&verified.instance, &args, options);
    spec.timeout = spec.timeout.max(Duration::from_secs(120));
    spec.cwd = verified.plan.action.cwd.as_deref().map(Into::into);
    spec.env.extend(verified.plan.action.env_overrides.clone());
    process::run(&spec).map_err(Into::into)
}

fn require_privileges(record: &InstallationRecord, plan: &RemovalPlan) -> Result<()> {
    let requires_root = record
        .metadata
        .get("requires_root")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !requires_root || has_root_privileges() {
        return Ok(());
    }
    let reason = record
        .metadata
        .get("privilege_reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("the selected package is in a system installation");
    let command = std::iter::once(plan.action.executable.as_str())
        .chain(plan.action.argv.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    bail!(
        "root privileges are required because {reason}; pkgscope never starts sudo automatically. Nothing was executed. Command: {command}"
    )
}

fn has_root_privileges() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        status.lines().find_map(|line| {
            let values = line.strip_prefix("Uid:")?;
            values
                .split_whitespace()
                .nth(1)
                .and_then(|effective| effective.parse::<u32>().ok())
        }) == Some(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn verify_system_removal_transaction(
    instance: &ManagerInstance,
    record: &InstallationRecord,
    plan: &RemovalPlan,
) -> Result<()> {
    match instance.manager {
        ManagerKind::Apt => verify_apt_transaction(instance, record),
        ManagerKind::Dnf => verify_dnf_transaction(instance, record),
        ManagerKind::Pacman => verify_pacman_transaction(instance, record),
        _ => Ok(()),
    }
    .with_context(|| {
        format!(
            "the removal transaction could not be proven to contain only {}; nothing was executed (planned command: {} {})",
            record.identity.name,
            plan.action.executable,
            plan.action.argv.join(" ")
        )
    })
}

fn verification_options() -> ScanOptions {
    ScanOptions {
        timeout: Duration::from_secs(60),
        offline: true,
        ..ScanOptions::default()
    }
}

fn verify_apt_transaction(instance: &ManagerInstance, record: &InstallationRecord) -> Result<()> {
    let options = verification_options();
    let dpkg = scanner::companion_executable(instance, &["dpkg"])
        .context("dpkg was not found beside apt-get or on PATH")?;
    let mut dpkg_instance = instance.clone();
    dpkg_instance.executable_path = dpkg.display().to_string();
    let mut dpkg_spec = scanner::manager_command_spec(
        &dpkg_instance,
        &["--dry-run", "--remove", "--", &record.identity.name],
        &options,
    );
    dpkg_spec.timeout = Duration::from_secs(60);
    process::run(&dpkg_spec).context("dpkg dependency check refused the target")?;

    let args = [
        "--simulate",
        "--no-auto-remove",
        "remove",
        "--",
        &record.identity.name,
    ];
    let spec = scanner::manager_command_spec(instance, &args, &options);
    let output = process::run(&spec).context("APT removal simulation failed")?;
    let text = format!("{}\n{}", output.stdout_text(), output.stderr_text());
    let changes = parse_apt_changes(&text);
    require_only_target(changes.removed, &record.identity.name)?;
    if !changes.installed.is_empty() {
        bail!(
            "APT simulation would also install or configure: {}",
            changes.installed.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

fn verify_dnf_transaction(instance: &ManagerInstance, record: &InstallationRecord) -> Result<()> {
    let options = verification_options();
    let package_spec = record
        .metadata
        .get("rpm_name_arch")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(&record.identity.name);
    let rpm = scanner::companion_executable(instance, &["rpm"])
        .context("rpm was not found beside dnf or on PATH")?;
    let mut rpm_instance = instance.clone();
    rpm_instance.executable_path = rpm.display().to_string();
    let rpm_spec = scanner::manager_command_spec(
        &rpm_instance,
        &["--erase", "--test", "--", package_spec],
        &options,
    );
    process::run(&rpm_spec).context("RPM dependency check refused the target")?;

    let args = [
        "--assumeno",
        "--setopt=clean_requirements_on_remove=False",
        "remove",
        package_spec,
    ];
    let spec = scanner::manager_command_spec(instance, &args, &options);
    let attempt = process::run_allow_failure(&spec).context("DNF removal simulation failed")?;
    let text = format!(
        "{}\n{}",
        attempt.output.stdout_text(),
        attempt.output.stderr_text()
    );
    let removed = parse_dnf_removals(&text);
    require_only_target(removed, &record.identity.name)
}

fn verify_pacman_transaction(
    instance: &ManagerInstance,
    record: &InstallationRecord,
) -> Result<()> {
    let options = verification_options();
    let args = [
        "-R",
        "--print",
        "--print-format",
        "%n",
        "--",
        &record.identity.name,
    ];
    let spec = scanner::manager_command_spec(instance, &args, &options);
    let output = process::run(&spec).context("pacman removal simulation failed")?;
    let removed = output
        .stdout_text()
        .lines()
        .map(crate::sanitize::terminal_text)
        .filter(|name| !name.is_empty())
        .collect();
    require_only_target(removed, &record.identity.name)
}

#[derive(Default)]
struct AptChanges {
    removed: BTreeSet<String>,
    installed: BTreeSet<String>,
}

fn parse_apt_changes(output: &str) -> AptChanges {
    let mut changes = AptChanges::default();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(operation) = fields.next() else {
            continue;
        };
        let Some(package) = fields.next() else {
            continue;
        };
        match operation {
            "Remv" | "Purg" => {
                changes.removed.insert(package.to_string());
            }
            "Inst" | "Conf" => {
                changes.installed.insert(package.to_string());
            }
            _ => {}
        }
    }
    changes
}

fn parse_dnf_removals(output: &str) -> BTreeSet<String> {
    let mut removed = BTreeSet::new();
    let mut in_removal_section = false;
    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if (lower.starts_with("removing") || lower.starts_with("erasing")) && lower.ends_with(':') {
            in_removal_section = true;
            continue;
        }
        if lower.starts_with("transaction summary")
            || lower.starts_with("after this operation")
            || lower.starts_with("operation aborted")
        {
            in_removal_section = false;
            continue;
        }
        if !in_removal_section
            || trimmed.is_empty()
            || trimmed.starts_with('=')
            || trimmed.starts_with('-')
        {
            continue;
        }
        let Some(name) = trimmed.split_whitespace().next() else {
            continue;
        };
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "package" | "architecture"
        ) {
            removed.insert(crate::sanitize::terminal_text(name));
        }
    }
    removed
}

fn require_only_target(mut removed: BTreeSet<String>, target: &str) -> Result<()> {
    let target_base = target.split(':').next().unwrap_or(target);
    let matches_target = removed.remove(target) || removed.remove(target_base);
    if !matches_target || !removed.is_empty() {
        let reported = if removed.is_empty() {
            "no exact target-only transaction".into()
        } else {
            removed.into_iter().collect::<Vec<_>>().join(", ")
        };
        bail!("transaction reported additional or missing removals: {reported}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path};

    use chrono::Utc;

    use super::*;
    use crate::model::{
        Category, Confidence, FieldValue, InstallIntent, InstallType, InstallationDates,
        InstallationPaths, InstallationSizes, ManagerKind, PackageIdentity, ScanScope, SourceKind,
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[cfg(unix)]
    fn verified_action_executes_direct_argv() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("args.txt");
        let manager_path = temp.path().join("npm");
        executable(
            &manager_path,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                marker.display()
            ),
        );
        let bin = temp.path().join("bin/demo");
        executable(&bin, "#!/bin/sh\nexit 0\n");
        let (snapshot, record) = fixture(&manager_path, &bin);
        let plan = build_removal_plan(&snapshot, &record).unwrap();
        let verified = revalidate_with_executable(
            &record,
            &plan,
            &snapshot,
            &temp.path().join("running-pkgscope"),
        )
        .unwrap();

        execute(&verified, &ScanOptions::default()).unwrap();

        assert_eq!(fs::read_to_string(marker).unwrap(), "uninstall\n-g\ndemo\n");
    }

    #[test]
    #[cfg(unix)]
    fn revalidation_blocks_current_executable_and_managed_dependents() {
        let temp = tempfile::tempdir().unwrap();
        let manager_path = temp.path().join("npm");
        executable(&manager_path, "#!/bin/sh\nexit 0\n");
        let bin = temp.path().join("bin/demo");
        executable(&bin, "#!/bin/sh\nexit 0\n");
        let (mut snapshot, record) = fixture(&manager_path, &bin);
        let plan = build_removal_plan(&snapshot, &record).unwrap();

        let self_error = revalidate_with_executable(&record, &plan, &snapshot, &bin)
            .unwrap_err()
            .to_string();
        assert!(self_error.contains("currently running"));

        let mut dependent = record_fixture("dependent", "dependent", "npm-instance", &bin);
        dependent.metadata.insert(
            "dependencies".into(),
            serde_json::json!([record.identity.name]),
        );
        snapshot.installations.push(dependent);
        let dependent_plan = build_removal_plan(&snapshot, &record).unwrap();
        let error = revalidate_with_executable(
            &record,
            &dependent_plan,
            &snapshot,
            &temp.path().join("other-pkgscope"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("managed dependents"));
    }

    #[test]
    fn apt_transaction_parser_rejects_additional_changes() {
        let exact = parse_apt_changes("Remv demo [1.0]\n");
        assert!(require_only_target(exact.removed, "demo").is_ok());

        let extra = parse_apt_changes("Remv demo [1.0]\nRemv libc6 [2.0]\n");
        assert!(require_only_target(extra.removed, "demo").is_err());

        let install = parse_apt_changes("Remv demo [1.0]\nInst replacement (2.0 repo)\n");
        assert_eq!(install.installed, BTreeSet::from(["replacement".into()]));
    }

    #[test]
    fn dnf_transaction_parser_includes_unused_dependencies() {
        let output = "Removing:\n demo x86_64 1.0 installed 1 M\nRemoving unused dependencies:\n helper x86_64 1.0 installed 1 M\nTransaction Summary\n";
        let removed = parse_dnf_removals(output);
        assert_eq!(removed, BTreeSet::from(["demo".into(), "helper".into()]));
        assert!(require_only_target(removed, "demo").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn all_eleven_managers_revalidate_and_execute_the_exact_direct_argv() {
        let cases = [
            (
                ManagerKind::Brew,
                "brew",
                SourceKind::Formula,
                "uninstall\ndemo\n",
            ),
            (
                ManagerKind::Npm,
                "npm",
                SourceKind::Registry,
                "uninstall\n-g\ndemo\n",
            ),
            (
                ManagerKind::Pnpm,
                "pnpm",
                SourceKind::Registry,
                "remove\n-g\ndemo\n",
            ),
            (
                ManagerKind::Pipx,
                "pipx",
                SourceKind::Registry,
                "uninstall\ndemo\n",
            ),
            (
                ManagerKind::Uv,
                "uv",
                SourceKind::Registry,
                "tool\nuninstall\ndemo\n",
            ),
            (
                ManagerKind::Cargo,
                "cargo",
                SourceKind::Registry,
                "uninstall\ndemo\n",
            ),
            (
                ManagerKind::Apt,
                "apt-get",
                SourceKind::Deb,
                "--assume-yes\n--no-auto-remove\nremove\n--\ndemo\n",
            ),
            (
                ManagerKind::Dnf,
                "dnf5",
                SourceKind::Rpm,
                "--assumeyes\n--setopt=clean_requirements_on_remove=False\nremove\ndemo.x86_64\n",
            ),
            (
                ManagerKind::Pacman,
                "pacman",
                SourceKind::Pacman,
                "-R\n--noconfirm\n--\ndemo\n",
            ),
            (
                ManagerKind::Snap,
                "snap",
                SourceKind::Snap,
                "remove\ndemo\n",
            ),
            (
                ManagerKind::Flatpak,
                "flatpak",
                SourceKind::Flatpak,
                "--user\nuninstall\n--noninteractive\n--no-related\napp/demo/x86_64/stable\n",
            ),
        ];

        for (manager, executable_name, source_kind, expected_argv) in cases {
            let temp = tempfile::tempdir().unwrap();
            let marker = temp.path().join("args.txt");
            let manager_path = temp.path().join(executable_name);
            let manager_script = match manager {
                ManagerKind::Apt => format!(
                    "#!/bin/sh\nif [ \"$1\" = --simulate ]; then printf 'Remv demo [1.0]\\n'; else printf '%s\\n' \"$@\" > '{}'; fi\n",
                    marker.display()
                ),
                ManagerKind::Dnf => format!(
                    "#!/bin/sh\nif [ \"$1\" = --assumeno ]; then printf 'Removing:\\n demo x86_64 1.0 installed 1 M\\nTransaction Summary\\n'; exit 1; else printf '%s\\n' \"$@\" > '{}'; fi\n",
                    marker.display()
                ),
                ManagerKind::Pacman => format!(
                    "#!/bin/sh\nif [ \"$#\" -eq 6 ] && [ \"$1\" = -R ] && [ \"$2\" = --print ] && [ \"$3\" = --print-format ] && [ \"$4\" = %n ] && [ \"$5\" = -- ] && [ \"$6\" = demo ]; then printf 'demo\\n'; elif [ \"$1\" = -R ] && [ \"$2\" = --noconfirm ]; then printf '%s\\n' \"$@\" > '{}'; else exit 64; fi\n",
                    marker.display()
                ),
                _ => format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                    marker.display()
                ),
            };
            executable(&manager_path, &manager_script);
            if manager == ManagerKind::Apt {
                executable(&temp.path().join("dpkg"), "#!/bin/sh\nexit 0\n");
            }
            if manager == ManagerKind::Dnf {
                executable(&temp.path().join("rpm"), "#!/bin/sh\nexit 0\n");
            }
            let bin = temp.path().join("bin/demo");
            executable(&bin, "#!/bin/sh\nexit 0\n");
            let (mut snapshot, mut record) = fixture(&manager_path, &bin);
            let instance = &mut snapshot.manager_instances[0];
            instance.manager = manager;
            instance.id = "manager-instance".into();
            instance.root = Some(temp.path().join("root").display().to_string());
            record.manager_instance_id = instance.id.clone();
            record.identity.ecosystem = manager.to_string();
            record.identity.source_kind = source_kind;
            if manager == ManagerKind::Dnf {
                record
                    .metadata
                    .insert("rpm_name_arch".into(), "demo.x86_64".into());
            }
            if manager == ManagerKind::Flatpak {
                record
                    .metadata
                    .insert("flatpak_installation".into(), "user".into());
                record
                    .metadata
                    .insert("flatpak_ref".into(), "app/demo/x86_64/stable".into());
            }
            snapshot.installations = vec![record.clone()];
            let plan = build_removal_plan(&snapshot, &record).unwrap();
            let verified = revalidate_with_executable(
                &record,
                &plan,
                &snapshot,
                &temp.path().join("other-pkgscope"),
            )
            .unwrap_or_else(|error| panic!("{manager} revalidation failed: {error:#}"));
            execute(&verified, &ScanOptions::default())
                .unwrap_or_else(|error| panic!("{manager} execution failed: {error:#}"));
            assert_eq!(
                fs::read_to_string(&marker).unwrap(),
                expected_argv,
                "wrong argv for {manager}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn root_required_records_are_refused_without_starting_sudo_or_the_manager() {
        if has_root_privileges() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("executed");
        let manager_path = temp.path().join("apt-get");
        executable(
            &manager_path,
            &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        );
        let bin = temp.path().join("bin/demo");
        executable(&bin, "#!/bin/sh\nexit 0\n");
        let (mut snapshot, mut record) = fixture(&manager_path, &bin);
        snapshot.manager_instances[0].manager = ManagerKind::Apt;
        record.identity.source_kind = SourceKind::Deb;
        record.metadata.insert("requires_root".into(), true.into());
        record.metadata.insert(
            "privilege_reason".into(),
            "APT modifies the system database".into(),
        );
        snapshot.installations = vec![record.clone()];
        let plan = build_removal_plan(&snapshot, &record).unwrap();
        let error = revalidate_with_executable(
            &record,
            &plan,
            &snapshot,
            &temp.path().join("other-pkgscope"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("never starts sudo"));
        assert!(error.contains("apt-get"));
        assert!(!marker.exists());
    }

    fn fixture(manager_path: &Path, bin: &Path) -> (Snapshot, InstallationRecord) {
        let mut snapshot = Snapshot::empty(ScanScope::default());
        snapshot.manager_instances.push(ManagerInstance {
            id: "npm-instance".into(),
            manager: ManagerKind::Npm,
            executable_path: manager_path.display().to_string(),
            root: Some("/fixture/node_modules".into()),
            runtime: None,
            runtime_manager: None,
            architecture: "arm64".into(),
            scope_owner: "current_user".into(),
            discovered_by: vec!["test".into()],
            scan_status: ScanStatus::Success,
            scanned_at: Utc::now(),
            capabilities: vec!["removal".into()],
        });
        let record = record_fixture("demo-id", "demo", "npm-instance", bin);
        snapshot.installations.push(record.clone());
        (snapshot, record)
    }

    fn record_fixture(
        id: &str,
        name: &str,
        manager_instance_id: &str,
        bin: &Path,
    ) -> InstallationRecord {
        InstallationRecord {
            id: id.into(),
            identity: PackageIdentity {
                ecosystem: "npm".into(),
                name: name.into(),
                source_kind: SourceKind::Registry,
                source_ref: None,
            },
            manager_instance_id: manager_instance_id.into(),
            category: Category::Cli,
            version: FieldValue::exact("1.0.0".into(), "test"),
            architecture: FieldValue::exact("arm64".into(), "test"),
            install_type: InstallType::Normal,
            intent: InstallIntent::Explicit,
            environment: "test".into(),
            paths: InstallationPaths {
                install_root: Some(format!("/fixture/{name}")),
                bins: vec![bin.display().to_string()],
                ..InstallationPaths::default()
            },
            dates: InstallationDates::default(),
            sizes: InstallationSizes {
                confidence: Confidence::Unknown,
                ..InstallationSizes::default()
            },
            command_ids: Vec::new(),
            finding_ids: Vec::new(),
            removal_plan_available: true,
            metadata: BTreeMap::new(),
        }
    }

    #[cfg(unix)]
    fn executable(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }
}
