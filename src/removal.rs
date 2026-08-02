use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};

use crate::{
    cli::build_removal_plan,
    model::{InstallationRecord, ManagerInstance, RemovalPlan, ScanStatus, Snapshot},
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
