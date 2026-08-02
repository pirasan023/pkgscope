use std::path::{Path, PathBuf};

use crate::model::{
    Category, Confidence, FieldValue, InstallIntent, InstallType, ManagerInstance, ScanStatus,
    SourceKind,
};
use crate::sanitize::terminal_text;

use super::{
    PartialScan, ScanOptions, command, command_error_code, insert_metadata_text, make_record,
    read_text_bounded,
};

const COLUMNS: &str =
    "application,version,arch,installation,origin,ref,size,name,description,runtime";

pub(super) fn scan(mut instance: ManagerInstance, options: &ScanOptions) -> PartialScan {
    let output = match command(
        &instance,
        &["list", "--app", &format!("--columns={COLUMNS}")],
        options,
    ) {
        Ok(output) => output,
        Err(error) => {
            let code = command_error_code(&error);
            return PartialScan::failed(instance, code, error);
        }
    };
    instance.root = Some("multiple_installations".into());
    let mut installations = Vec::new();
    let mut commands = Vec::new();
    for app in parse_list(&output.stdout_text()) {
        let scope_args = scope_args(&app.installation);
        let root = flatpak_location(&instance, &scope_args, &app.reference, options);
        let mut scan_options = options.clone();
        scan_options.calculate_sizes = false;
        let (mut record, record_commands) = make_record(
            &instance,
            &app.application,
            app.version.as_deref(),
            "flatpak",
            SourceKind::Flatpak,
            Some(app.origin.clone()),
            root.clone(),
            Vec::new(),
            Category::App,
            InstallType::Normal,
            InstallIntent::Explicit,
            &scan_options,
        );
        record.environment = if app.installation == "user" {
            "user".into()
        } else if matches!(app.installation.as_str(), "system" | "default") {
            "system".into()
        } else {
            format!("system:{}", app.installation)
        };
        record.version = app.version.map_or_else(
            || FieldValue::unknown("flatpak_list"),
            |version| FieldValue::exact(version, "flatpak_list"),
        );
        record.architecture = if app.architecture.is_empty() {
            FieldValue::unknown("flatpak_list")
        } else {
            FieldValue::exact(normalize_architecture(&app.architecture), "flatpak_list")
        };
        if let Some(size) = app.installed_size {
            record.sizes.owned_apparent_bytes = Some(size);
            record.sizes.owned_allocated_bytes = Some(size);
            record.sizes.estimated_reclaimable_bytes = Some(size);
            record.sizes.confidence = Confidence::Estimated;
            record.sizes.method = "flatpak_reported_installed_size".into();
        }
        insert_metadata_text(&mut record, "description", Some(&app.description));
        if record.metadata.contains_key("description") {
            record
                .metadata
                .insert("description_source".into(), "flatpak_list".into());
        }
        if let Some(root) = &root {
            enrich_from_appstream(&mut record, root);
        }
        record
            .metadata
            .insert("flatpak_ref".into(), app.reference.into());
        record.metadata.insert(
            "flatpak_installation".into(),
            app.installation.clone().into(),
        );
        record.metadata.insert("origin".into(), app.origin.into());
        record.metadata.insert("name".into(), app.name.into());
        if let Some(runtime) = app.runtime {
            record.metadata.insert("runtime".into(), runtime.into());
        }
        record.metadata.insert(
            "launch_argv".into(),
            serde_json::json!(["flatpak", "run", record.identity.name]),
        );
        record
            .metadata
            .insert("delete_user_data".into(), false.into());
        let requires_root = app.installation != "user";
        record
            .metadata
            .insert("requires_root".into(), requires_root.into());
        if requires_root {
            record.metadata.insert(
                "privilege_reason".into(),
                "Flatpak application is installed in a system installation".into(),
            );
        }
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

struct FlatpakApp {
    application: String,
    version: Option<String>,
    architecture: String,
    installation: String,
    origin: String,
    reference: String,
    installed_size: Option<u64>,
    name: String,
    description: String,
    runtime: Option<String>,
}

fn parse_list(output: &str) -> Vec<FlatpakApp> {
    output
        .lines()
        .filter_map(|line| {
            let fields = line.splitn(10, '\t').map(terminal_text).collect::<Vec<_>>();
            if fields.len() < 10
                || fields[0].is_empty()
                || matches!(fields[0].as_str(), "Application" | "Application ID")
            {
                return None;
            }
            Some(FlatpakApp {
                application: fields[0].clone(),
                version: (!fields[1].is_empty()).then(|| fields[1].clone()),
                architecture: fields[2].clone(),
                installation: normalize_installation(&fields[3]),
                origin: fields[4].clone(),
                reference: fields[5].clone(),
                installed_size: parse_size(&fields[6]),
                name: fields[7].clone(),
                description: fields[8].clone(),
                runtime: (!fields[9].is_empty()).then(|| fields[9].clone()),
            })
        })
        .collect()
}

pub(crate) fn scope_args(installation: &str) -> Vec<String> {
    match installation {
        "user" => vec!["--user".into()],
        "system" | "default" => vec!["--system".into()],
        name => vec![format!("--installation={name}")],
    }
}

fn flatpak_location(
    instance: &ManagerInstance,
    scope_args: &[String],
    reference: &str,
    options: &ScanOptions,
) -> Option<PathBuf> {
    let mut args = scope_args.to_vec();
    args.extend(["info".into(), "--show-location".into(), reference.into()]);
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    command(instance, &args, options)
        .ok()
        .map(|output| PathBuf::from(output.stdout_text().trim()))
        .filter(|path| !path.as_os_str().is_empty())
}

fn parse_size(value: &str) -> Option<u64> {
    let normalized = value.replace(',', ".");
    let mut parts = normalized.split_whitespace();
    let number: f64 = parts.next()?.parse().ok()?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    let multiplier = match parts
        .next()
        .unwrap_or("bytes")
        .to_ascii_lowercase()
        .as_str()
    {
        "b" | "byte" | "bytes" => 1_f64,
        "kb" => 1_000_f64,
        "mb" => 1_000_000_f64,
        "gb" => 1_000_000_000_f64,
        "tb" => 1_000_000_000_000_f64,
        "kib" => 1_024_f64,
        "mib" => 1_048_576_f64,
        "gib" => 1_073_741_824_f64,
        _ => return None,
    };
    Some((number * multiplier).round().min(u64::MAX as f64) as u64)
}

fn normalize_architecture(value: &str) -> String {
    match value {
        "aarch64" => "arm64".into(),
        "amd64" => "x86_64".into(),
        value => value.into(),
    }
}

fn normalize_installation(value: &str) -> String {
    value
        .strip_prefix("system (")
        .and_then(|value| value.strip_suffix(')'))
        .map_or_else(|| value.to_string(), str::to_string)
}

fn enrich_from_appstream(record: &mut crate::model::InstallationRecord, root: &Path) {
    for entry in walkdir::WalkDir::new(root.join("files/share/metainfo"))
        .max_depth(2)
        .follow_links(false)
        .into_iter()
        .flatten()
        .take(1_000)
    {
        let extension = entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str());
        if extension != Some("xml") {
            continue;
        }
        let Ok(contents) = read_text_bounded(entry.path(), 2 * 1024 * 1024) else {
            continue;
        };
        if let Some(homepage) = xml_homepage(&contents) {
            insert_metadata_text(record, "homepage", Some(&homepage));
        }
        return;
    }
}

fn xml_homepage(contents: &str) -> Option<String> {
    let marker = "<url type=\"homepage\">";
    let start = contents.find(marker)? + marker.len();
    let end = contents[start..].find("</url>")? + start;
    let value = terminal_text(contents[start..end].trim());
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scopes_and_future_columns_safely() {
        let rows = parse_list(
            "Application\tVersion\tArch\tInstallation\tOrigin\tRef\tSize\tName\tDescription\tRuntime\norg.demo.App\t1.0\tx86_64\textra\tlocal\tapp/org.demo.App/x86_64/stable\t1.5 MB\tDemo\tDemo app\torg.demo.Runtime/x86_64/1\n",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].installed_size, Some(1_500_000));
        assert_eq!(scope_args("extra"), vec!["--installation=extra"]);
        assert_eq!(normalize_installation("system (extra)"), "extra");
    }

    #[test]
    fn rejects_corrupt_sizes_without_guessing() {
        assert_eq!(parse_size("unknown"), None);
        assert_eq!(parse_size("NaN MB"), None);
    }
}
