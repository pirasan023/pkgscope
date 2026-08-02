use std::path::{Path, PathBuf};

use chrono::DateTime;

use crate::model::{
    Category, Confidence, FieldValue, InstallIntent, InstallType, InstallationDates,
    ManagerInstance, ScanStatus, SourceKind,
};
use crate::{process, sanitize::terminal_text};

use super::{
    PartialScan, ScanOptions, command, command_error_code, companion_command, insert_metadata_text,
    make_record,
};

const RPM_QUERY_FORMAT: &str = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{INSTALLTIME}\t%{SUMMARY}\t%{URL}\n";

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let output = command(
        &instance,
        &[
            "--cacheonly",
            "--quiet",
            "repoquery",
            "--installed",
            "--userinstalled",
            "--queryformat",
            "%{name}\\n",
        ],
        options,
    )
    .or_else(|_| {
        // DNF5 treats --userinstalled as an installed-package selector and
        // rejects combining it with --installed; DNF4 accepts the first form.
        command(
            &instance,
            &[
                "--cacheonly",
                "--quiet",
                "repoquery",
                "--userinstalled",
                "--queryformat",
                "%{name}\\n",
            ],
            options,
        )
    });
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let explicit = output
        .stdout_text()
        .lines()
        .map(terminal_text)
        .filter(|name| !name.is_empty())
        .collect::<std::collections::BTreeSet<_>>();
    instance.root = Some("/var/lib/rpm".into());
    if explicit.is_empty() {
        instance.scan_status = ScanStatus::Success;
        return PartialScan {
            instance,
            installations: Vec::new(),
            commands: Vec::new(),
            errors: Vec::new(),
        };
    }
    let rpm = match companion_command(
        &instance,
        &["rpm"],
        &["-qa", "--queryformat", RPM_QUERY_FORMAT],
        options,
    ) {
        Ok(output) => output,
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    for package in parse_packages(&rpm.stdout_text()) {
        if !explicit.contains(&package.name) {
            continue;
        }
        let package_spec = format!("{}.{}", package.name, package.architecture);
        let bins = rpm_files(&instance, &package_spec, options)
            .into_iter()
            .filter(|path| is_command_path(path) && process::is_executable(path))
            .collect();
        let (mut record, record_commands) = make_record(
            &instance,
            &package.name,
            Some(&package.version),
            "rpm",
            SourceKind::Rpm,
            None,
            None,
            bins,
            Category::Other,
            InstallType::Normal,
            InstallIntent::Explicit,
            options,
        );
        record.category = if record_commands.is_empty() {
            Category::Other
        } else {
            Category::Cli
        };
        record.version = FieldValue::exact(package.version, "rpm_database");
        record.architecture = FieldValue::exact(package.architecture.clone(), "rpm_database");
        record.sizes.owned_apparent_bytes = Some(package.installed_size);
        record.sizes.owned_allocated_bytes = Some(package.installed_size);
        record.sizes.estimated_reclaimable_bytes = Some(package.installed_size);
        record.sizes.confidence = Confidence::Estimated;
        record.sizes.method = "rpm_installed_size".into();
        if let Some(installed_at) = DateTime::from_timestamp(package.install_time, 0) {
            record.dates = InstallationDates {
                manager_install_event_at: Some(FieldValue::exact(installed_at, "rpm_installtime")),
                current_version_installed_at: Some(FieldValue::exact(
                    installed_at,
                    "rpm_installtime",
                )),
                ..record.dates
            };
        }
        insert_metadata_text(
            &mut record,
            "description",
            local_rpm_value(&package.summary),
        );
        if record.metadata.contains_key("description") {
            record
                .metadata
                .insert("description_source".into(), "rpm_database".into());
        }
        insert_metadata_text(&mut record, "homepage", local_rpm_value(&package.url));
        record.metadata.insert("requires_root".into(), true.into());
        record.metadata.insert(
            "privilege_reason".into(),
            "DNF modifies the system RPM database".into(),
        );
        record.metadata.insert(
            "rpm_name_arch".into(),
            format!("{}.{}", package.name, package.architecture).into(),
        );
        commands.extend(record_commands);
        installations.push(record);
    }
    instance.scan_status = ScanStatus::Success;
    PartialScan {
        instance,
        installations,
        commands,
        errors: Vec::new(),
    }
}

struct RpmPackage {
    name: String,
    version: String,
    architecture: String,
    installed_size: u64,
    install_time: i64,
    summary: String,
    url: String,
}

fn parse_packages(output: &str) -> Vec<RpmPackage> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(7, '\t').map(terminal_text);
            let name = fields.next()?;
            let raw_version = fields.next()?;
            let version = raw_version
                .strip_prefix("0:")
                .unwrap_or(&raw_version)
                .to_string();
            let architecture = fields.next()?;
            let installed_size = fields.next()?.parse().ok()?;
            let install_time = fields.next()?.parse().ok()?;
            let summary = fields.next()?;
            let url = fields.next().unwrap_or_default();
            (!name.is_empty() && !version.is_empty()).then_some(RpmPackage {
                name,
                version,
                architecture,
                installed_size,
                install_time,
                summary,
                url,
            })
        })
        .collect()
}

fn rpm_files(instance: &ManagerInstance, name: &str, options: &ScanOptions) -> Vec<PathBuf> {
    companion_command(instance, &["rpm"], &["-ql", name], options)
        .ok()
        .map(|output| {
            output
                .stdout_text()
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with('/'))
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

fn local_rpm_value(value: &str) -> Option<&str> {
    (!value.is_empty() && value != "(none)").then_some(value)
}

fn is_command_path(path: &Path) -> bool {
    [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/local/bin/",
    ]
    .iter()
    .any(|prefix| path.to_string_lossy().starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rpm_query_and_ignores_unknown_trailing_fields() {
        let packages = parse_packages(
            "demo\t0:1.2-3\tx86_64\t4096\t1700000000\tDemo tool\thttps://example.test\textra\n",
        );
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].version, "1.2-3");
        assert_eq!(packages[0].installed_size, 4096);
    }
}
