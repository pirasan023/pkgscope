use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::{Path, PathBuf},
};

use chrono::Utc;

use crate::{
    model::{CommandExposure, Confidence, ExposureState, Finding, Severity, Snapshot, stable_id},
    process,
};

pub fn apply_findings(snapshot: &mut Snapshot) {
    let previous_first_seen: HashMap<_, _> = snapshot
        .findings
        .iter()
        .map(|finding| (finding.id.clone(), finding.first_seen_at))
        .collect();
    snapshot.findings.clear();
    for installation in &mut snapshot.installations {
        installation.finding_ids.clear();
    }
    resolve_path(&mut snapshot.commands);
    detect_duplicate_packages(snapshot);
    detect_command_collisions(snapshot);
    detect_shadowed_commands(snapshot);
    detect_broken_commands(snapshot);
    detect_owner_mismatches(snapshot);
    detect_missing_runtimes(snapshot);
    add_partial_data_findings(snapshot);
    for finding in &mut snapshot.findings {
        if let Some(first_seen_at) = previous_first_seen.get(&finding.id) {
            finding.first_seen_at = *first_seen_at;
        }
    }

    let links: Vec<(String, Vec<String>)> = snapshot
        .findings
        .iter()
        .flat_map(|finding| {
            finding
                .installation_ids
                .iter()
                .map(move |installation_id| (installation_id.clone(), vec![finding.id.clone()]))
        })
        .collect();
    for installation in &mut snapshot.installations {
        for (_, finding_ids) in links.iter().filter(|(id, _)| id == &installation.id) {
            installation.finding_ids.extend(finding_ids.clone());
        }
        installation.finding_ids.sort();
        installation.finding_ids.dedup();
    }
}

fn resolve_path(commands: &mut [CommandExposure]) {
    let path_directories: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect())
        .unwrap_or_default();
    let mut candidate_cache: HashMap<String, Vec<(usize, PathBuf, Option<PathBuf>)>> =
        HashMap::new();
    for command in commands {
        if command.exposure_state == ExposureState::Broken {
            continue;
        }
        let candidates = candidate_cache
            .entry(command.name.clone())
            .or_insert_with(|| {
                path_directories
                    .iter()
                    .enumerate()
                    .filter_map(|(rank, directory)| {
                        let path = directory.join(&command.name);
                        process::is_executable(&path).then(|| {
                            let canonical = path.canonicalize().ok();
                            (rank + 1, path, canonical)
                        })
                    })
                    .collect()
            });
        let command_path = PathBuf::from(&command.path);
        let command_real = command_path.canonicalize().ok();
        let match_rank = candidates.iter().find_map(|(rank, path, canonical)| {
            (path == &command_path
                || canonical.as_ref().is_some_and(|candidate| {
                    command_real.as_ref().is_some_and(|real| real == candidate)
                }))
            .then_some(*rank)
        });
        command.path_rank = match_rank;
        command.on_current_path = match_rank.is_some();
        command.exposure_state = match match_rank {
            Some(rank)
                if candidates
                    .first()
                    .is_some_and(|(first, _, _)| *first == rank) =>
            {
                ExposureState::Active
            }
            Some(_) => ExposureState::Shadowed,
            None => ExposureState::Hidden,
        };
    }
}

fn detect_duplicate_packages(snapshot: &mut Snapshot) {
    let mut groups: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for record in &snapshot.installations {
        groups
            .entry((
                record.identity.ecosystem.to_ascii_lowercase(),
                canonical_name(&record.identity.name),
            ))
            .or_default()
            .push(record.id.clone());
    }
    for ((ecosystem, name), mut ids) in groups {
        ids.sort();
        ids.dedup();
        if ids.len() < 2 {
            continue;
        }
        push_finding(
            snapshot,
            "duplicate_package",
            Severity::Review,
            Confidence::High,
            ids,
            Vec::new(),
            Vec::new(),
            format!("Multiple managed installations of {name}"),
            format!(
                "The same canonical {ecosystem} package appears in more than one manager instance. This can be intentional; compare environment, version, architecture, and PATH state before acting."
            ),
            Some("Review each environment; no installation is automatically recommended for removal.".into()),
        );
    }
}

fn detect_command_collisions(snapshot: &mut Snapshot) {
    let mut groups: BTreeMap<String, Vec<&CommandExposure>> = BTreeMap::new();
    for command in &snapshot.commands {
        groups
            .entry(command.name.clone())
            .or_default()
            .push(command);
    }
    let findings: Vec<_> = groups
        .into_iter()
        .filter_map(|(name, commands)| {
            let mut installation_ids: Vec<_> = commands
                .iter()
                .map(|command| command.owner_installation_id.clone())
                .collect();
            installation_ids.sort();
            installation_ids.dedup();
            if installation_ids.len() < 2 {
                return None;
            }
            let mut command_ids: Vec<_> =
                commands.iter().map(|command| command.id.clone()).collect();
            command_ids.sort();
            Some((name, installation_ids, command_ids))
        })
        .collect();
    for (name, installation_ids, command_ids) in findings {
        push_finding(
            snapshot,
            "command_collision",
            Severity::Warning,
            Confidence::High,
            installation_ids,
            command_ids,
            Vec::new(),
            format!("Multiple installations expose the command {name}"),
            "More than one managed installation publishes this command name. The active candidate depends on the current PATH and may differ in other shells or GUI applications.".into(),
            Some("Inspect all candidates and the current PATH rank before changing an installation.".into()),
        );
    }
}

fn detect_shadowed_commands(snapshot: &mut Snapshot) {
    let shadowed: Vec<_> = snapshot
        .commands
        .iter()
        .filter(|command| command.exposure_state == ExposureState::Shadowed)
        .map(|command| {
            (
                command.owner_installation_id.clone(),
                command.id.clone(),
                command.name.clone(),
                command.path_rank,
            )
        })
        .collect();
    for (installation_id, command_id, name, rank) in shadowed {
        push_finding(
            snapshot,
            "shadowed_command",
            Severity::Review,
            Confidence::High,
            vec![installation_id],
            vec![command_id],
            Vec::new(),
            format!("{name} is shadowed on the current PATH"),
            format!(
                "This exposure is present on PATH at rank {}, but another executable with the same name is resolved first.",
                rank.unwrap_or_default()
            ),
            Some("Inspect the first PATH candidate and decide whether this alternate environment is still needed.".into()),
        );
    }
}

fn detect_broken_commands(snapshot: &mut Snapshot) {
    let broken: Vec<_> = snapshot
        .commands
        .iter_mut()
        .filter_map(|command| {
            let path = PathBuf::from(&command.path);
            let reason = broken_reason(&path);
            if reason.is_some() {
                command.exposure_state = ExposureState::Broken;
            }
            reason.map(|reason| {
                (
                    command.owner_installation_id.clone(),
                    command.id.clone(),
                    command.name.clone(),
                    reason,
                )
            })
        })
        .collect();
    for (installation_id, command_id, name, reason) in broken {
        push_finding(
            snapshot,
            "broken_command",
            Severity::Critical,
            Confidence::High,
            vec![installation_id],
            vec![command_id],
            Vec::new(),
            format!("{name} is not executable"),
            reason,
            Some("Repair or reinstall it with its owning manager; pkgscope will not delete files directly.".into()),
        );
    }
}

fn detect_missing_runtimes(snapshot: &mut Snapshot) {
    let missing: Vec<_> = snapshot
        .installations
        .iter()
        .filter_map(|record| {
            let interpreter = record
                .metadata
                .get("python_interpreter")
                .and_then(serde_json::Value::as_str)?;
            (!Path::new(interpreter).exists()).then(|| {
                (
                    record.id.clone(),
                    record.identity.name.clone(),
                    interpreter.to_string(),
                )
            })
        })
        .collect();
    for (installation_id, name, interpreter) in missing {
        push_finding(
            snapshot,
            "broken_runtime",
            Severity::Critical,
            Confidence::High,
            vec![installation_id],
            Vec::new(),
            Vec::new(),
            format!("{name} has a missing Python interpreter"),
            format!("The managed environment expects {interpreter}, but that path does not exist."),
            Some("Repair or reinstall the environment with its owning manager.".into()),
        );
    }
}

fn detect_owner_mismatches(snapshot: &mut Snapshot) {
    let records: HashMap<_, _> = snapshot
        .installations
        .iter()
        .filter_map(|record| {
            let instance = snapshot
                .manager_instances
                .iter()
                .find(|instance| instance.id == record.manager_instance_id)?;
            if !matches!(
                instance.manager,
                crate::model::ManagerKind::Npm | crate::model::ManagerKind::Pnpm
            ) {
                return None;
            }
            let root = record.paths.install_root.as_deref()?;
            Some((
                record.id.clone(),
                (record.identity.name.clone(), root.to_string()),
            ))
        })
        .collect();
    let mismatches: Vec<_> = snapshot
        .commands
        .iter_mut()
        .filter_map(|command| {
            let (package_name, root) = records.get(&command.owner_installation_id)?;
            let path = Path::new(&command.path);
            let metadata = fs::symlink_metadata(path).ok()?;
            if !metadata.file_type().is_symlink() {
                return None;
            }
            let real_path = path.canonicalize().ok()?;
            let real_root = Path::new(root).canonicalize().ok()?;
            if real_path.starts_with(real_root) {
                return None;
            }
            command.exposure_state = ExposureState::Broken;
            Some((
                command.owner_installation_id.clone(),
                command.id.clone(),
                package_name.clone(),
                command.name.clone(),
                real_path.display().to_string(),
            ))
        })
        .collect();
    for (installation_id, command_id, package, command, target) in mismatches {
        push_finding(
            snapshot,
            "broken_owner_metadata",
            Severity::Critical,
            Confidence::High,
            vec![installation_id],
            vec![command_id],
            Vec::new(),
            format!("{command} does not point into {package}"),
            format!("The manager record declares ownership, but the exposed link resolves to {target}. It may have been overwritten by another installation."),
            Some("Reconcile the conflicting installations with their managers; do not delete the link directly.".into()),
        );
    }
}

fn add_partial_data_findings(snapshot: &mut Snapshot) {
    let failures: Vec<_> = snapshot
        .manager_instances
        .iter()
        .filter(|instance| instance.scan_status != crate::model::ScanStatus::Success)
        .map(|instance| (instance.manager, instance.id.clone(), instance.scan_status))
        .collect();
    for (manager, instance_id, status) in failures {
        push_finding(
            snapshot,
            "partial_data",
            Severity::Warning,
            Confidence::Exact,
            Vec::new(),
            Vec::new(),
            vec![instance_id.clone()],
            format!("{manager} inventory is incomplete"),
            format!(
                "The manager instance {instance_id} ended with status {status:?}. No old records were silently presented as current."
            ),
            Some(
                "Run pkgscope doctor or rescan with --verbose after checking the manager directly."
                    .into(),
            ),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_finding(
    snapshot: &mut Snapshot,
    code: &str,
    severity: Severity,
    confidence: Confidence,
    installation_ids: Vec<String>,
    command_ids: Vec<String>,
    evidence_refs: Vec<String>,
    title: String,
    explanation: String,
    suggested_action: Option<String>,
) {
    let now = Utc::now();
    let mut identity_parts = vec![code.to_string()];
    identity_parts.extend(installation_ids.iter().cloned());
    identity_parts.extend(command_ids.iter().cloned());
    identity_parts.extend(evidence_refs.iter().cloned());
    let refs: Vec<&str> = identity_parts.iter().map(String::as_str).collect();
    snapshot.findings.push(Finding {
        id: stable_id(&refs),
        code: code.into(),
        severity,
        confidence,
        installation_ids,
        command_ids,
        title: crate::sanitize::terminal_text(&title),
        explanation: crate::sanitize::terminal_text(&explanation),
        evidence_refs,
        suggested_action,
        first_seen_at: now,
        last_seen_at: now,
    });
}

fn canonical_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '_' | '.' => '-',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

fn broken_reason(path: &Path) -> Option<String> {
    let symlink = fs::symlink_metadata(path);
    let Ok(metadata) = symlink else {
        return Some("The exposed path is missing or is a broken symbolic link.".into());
    };
    if metadata.file_type().is_symlink() && path.metadata().is_err() {
        return Some("The exposed path is a symbolic link whose target does not exist.".into());
    }
    if path.is_file() && !process::is_executable(path) {
        return Some("The exposed file does not have executable permissions.".into());
    }
    missing_shebang_interpreter(path)
}

fn missing_shebang_interpreter(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let mut bytes = [0_u8; 512];
    let count = file.read(&mut bytes).ok()?;
    let first = std::str::from_utf8(&bytes[..count]).ok()?.lines().next()?;
    let shebang = first.strip_prefix("#!")?.trim();
    let mut parts = shebang.split_whitespace();
    let interpreter = parts.next()?;
    if interpreter == "/usr/bin/env" {
        let command = parts.find(|part| !part.starts_with('-'))?;
        if process::find_executables(command).is_empty() {
            return Some(format!(
                "The shebang requires {command}, which is not available on the current PATH."
            ));
        }
    } else if interpreter.starts_with('/') && !Path::new(interpreter).exists() {
        return Some(format!(
            "The shebang interpreter {interpreter} does not exist."
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{io::Write, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn spots_missing_shebang_interpreter() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("tool");
        let mut file = fs::File::create(&path).unwrap();
        writeln!(file, "#!/definitely/missing/interpreter").unwrap();
        let mut permissions = file.metadata().unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        assert!(broken_reason(&path).unwrap().contains("does not exist"));
    }
}
