use std::{
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering as AtomicOrdering},
};

use anyhow::Result;
use clap::ValueEnum;
use serde::Serialize;
use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

use crate::model::{Finding, InstallationRecord, ManagerInstance, RemovalPlan, Severity, Snapshot};

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_color_enabled(enabled: bool) {
    COLOR_ENABLED.store(enabled, AtomicOrdering::Relaxed);
}

pub fn color_enabled() -> bool {
    COLOR_ENABLED.load(AtomicOrdering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Jsonl,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SortField {
    Name,
    Manager,
    Environment,
    Version,
    Size,
    KnownSince,
    Findings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SortOrder {
    Asc,
    Desc,
}

pub fn installations(
    snapshot: &Snapshot,
    format: OutputFormat,
    sort: SortField,
    order: SortOrder,
) -> Result<()> {
    let mut records: Vec<_> = snapshot.installations.iter().collect();
    sort_records(&mut records, sort, order, snapshot);
    match format {
        OutputFormat::Table => installation_table(snapshot, &records),
        OutputFormat::Json => json(snapshot),
        OutputFormat::Jsonl => jsonl(snapshot),
        OutputFormat::Csv => installation_csv(snapshot, &records),
    }
}

pub fn json(value: &impl Serialize) -> Result<()> {
    serde_json::to_writer_pretty(io::stdout().lock(), value)?;
    println!();
    Ok(())
}

fn jsonl(snapshot: &Snapshot) -> Result<()> {
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "{}",
        serde_json::json!({
            "schema_version": snapshot.schema_version,
            "generated_at": snapshot.generated_at,
            "scan_id": snapshot.scan_id,
            "type": "scan"
        })
    )?;
    for instance in &snapshot.manager_instances {
        write_jsonl(&mut output, snapshot, "manager_instance", instance)?;
    }
    for installation in &snapshot.installations {
        write_jsonl(&mut output, snapshot, "installation", installation)?;
    }
    for command in &snapshot.commands {
        write_jsonl(&mut output, snapshot, "command", command)?;
    }
    for finding in &snapshot.findings {
        write_jsonl(&mut output, snapshot, "finding", finding)?;
    }
    for error in &snapshot.errors {
        write_jsonl(&mut output, snapshot, "error", error)?;
    }
    Ok(())
}

fn write_jsonl(
    output: &mut impl Write,
    snapshot: &Snapshot,
    kind: &str,
    data: &impl Serialize,
) -> Result<()> {
    writeln!(
        output,
        "{}",
        serde_json::json!({
            "schema_version": snapshot.schema_version,
            "scan_id": snapshot.scan_id,
            "type": kind,
            "data": data
        })
    )?;
    Ok(())
}

fn installation_table(snapshot: &Snapshot, records: &[&InstallationRecord]) -> Result<()> {
    let width = terminal_width();
    let show_environment = width >= 92;
    let show_known = width >= 78;
    let show_findings = width >= 68;
    let other_columns = 8
        + 12
        + 11
        + usize::from(show_environment) * 14
        + usize::from(show_known) * 13
        + usize::from(show_findings) * 17;
    let column_count =
        4 + usize::from(show_environment) + usize::from(show_known) + usize::from(show_findings);
    let gaps = column_count.saturating_sub(1);
    let name_width = width.saturating_sub(other_columns + gaps).clamp(1, 34);
    let mut headers = vec![("NAME", name_width), ("MANAGER", 8)];
    if show_environment {
        headers.push(("ENVIRONMENT", 14));
    }
    headers.extend([("VERSION", 12), ("SIZE", 11)]);
    if show_known {
        headers.push(("KNOWN SINCE", 13));
    }
    if show_findings {
        headers.push(("FINDINGS", 17));
    }
    let scope = if snapshot.scope.requested_managers.is_empty() {
        format!("{:?}", snapshot.scope.environment_mode).to_ascii_lowercase()
    } else {
        format!(
            "managers={}",
            snapshot
                .scope
                .requested_managers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let headline = format!(
        "pkgscope — {} managed installations — {}{} — {}",
        records.len(),
        scope,
        if snapshot.partial { " — PARTIAL" } else { "" },
        snapshot.generated_at.to_rfc3339(),
    );
    println!("{}", truncate(&headline, width));
    println!(
        "{}",
        headers
            .iter()
            .map(|(name, width)| pad(name, *width))
            .collect::<Vec<_>>()
            .join(" ")
    );
    for record in records {
        let manager = manager_for(snapshot, record)
            .map(|instance| instance.manager.to_string())
            .unwrap_or_else(|| "Unknown".into());
        let mut columns = vec![pad(&record.identity.name, name_width), pad(&manager, 8)];
        if show_environment {
            columns.push(pad(&record.environment, 14));
        }
        columns.push(pad(
            record.version.value.as_deref().unwrap_or("Unknown"),
            12,
        ));
        columns.push(pad(&size_label(record.sizes.owned_allocated_bytes), 11));
        if show_known {
            columns.push(pad(&known_since(record), 13));
        }
        if show_findings {
            columns.push(pad(&finding_codes(snapshot, record), 17));
        }
        println!("{}", columns.join(" "));
    }
    if records.is_empty() {
        println!("No supported managed installations found in the scanned environments.");
    }
    if snapshot.partial {
        eprintln!(
            "warning: scan completed with partial data ({} scanner error(s)); successful results are shown",
            snapshot.errors.len()
        );
    }
    Ok(())
}

fn installation_csv(snapshot: &Snapshot, records: &[&InstallationRecord]) -> Result<()> {
    let mut writer = csv::Writer::from_writer(io::stdout().lock());
    writer.write_record([
        "id",
        "name",
        "ecosystem",
        "manager",
        "manager_instance_id",
        "environment",
        "version",
        "architecture",
        "install_root",
        "owned_apparent_bytes",
        "owned_allocated_bytes",
        "known_since",
        "findings",
    ])?;
    for record in records {
        writer.write_record([
            record.id.as_str(),
            record.identity.name.as_str(),
            record.identity.ecosystem.as_str(),
            manager_for(snapshot, record)
                .map(|value| value.manager.executable())
                .unwrap_or("unknown"),
            record.manager_instance_id.as_str(),
            record.environment.as_str(),
            record.version.value.as_deref().unwrap_or(""),
            record.architecture.value.as_deref().unwrap_or(""),
            record.paths.install_root.as_deref().unwrap_or(""),
            &record
                .sizes
                .owned_apparent_bytes
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &record
                .sizes
                .owned_allocated_bytes
                .map(|value| value.to_string())
                .unwrap_or_default(),
            &known_since(record),
            &finding_codes(snapshot, record),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

pub fn inspect(
    snapshot: &Snapshot,
    record: &InstallationRecord,
    format: OutputFormat,
) -> Result<()> {
    if format == OutputFormat::Json {
        return json(&serde_json::json!({
            "schema_version": snapshot.schema_version,
            "generated_at": snapshot.generated_at,
            "scan_id": snapshot.scan_id,
            "installation": record,
            "manager_instance": manager_for(snapshot, record),
            "commands": snapshot.commands.iter().filter(|command| command.owner_installation_id == record.id).collect::<Vec<_>>(),
            "findings": snapshot.findings.iter().filter(|finding| finding.installation_ids.contains(&record.id)).collect::<Vec<_>>()
        }));
    }
    let manager = manager_for(snapshot, record);
    println!("{}", record.identity.name);
    println!(
        "  Description:        {} [{}]",
        metadata_text(record, "description")
            .unwrap_or("No description was provided by the installed package metadata."),
        metadata_text(record, "description_source").unwrap_or("not reported")
    );
    println!(
        "  Homepage:           {}",
        metadata_text(record, "homepage").unwrap_or("Not reported")
    );
    println!("  ID:                 {}", record.id);
    println!(
        "  Manager:            {}",
        manager
            .map(|instance| format!("{} ({})", instance.manager, instance.executable_path))
            .unwrap_or_else(|| "Unknown".into())
    );
    println!("  Environment:        {}", record.environment);
    println!(
        "  Source:             {:?}{}",
        record.identity.source_kind,
        record
            .identity
            .source_ref
            .as_deref()
            .map(|source| format!(" ({source})"))
            .unwrap_or_default()
    );
    println!(
        "  Version:            {} ({}, {})",
        record.version.value.as_deref().unwrap_or("Unknown"),
        record.version.source,
        confidence_label(record.version.confidence)
    );
    println!(
        "  Architecture:       {}",
        record.architecture.value.as_deref().unwrap_or("Unknown")
    );
    println!(
        "  Install root:       {}",
        record.paths.install_root.as_deref().unwrap_or("Unknown")
    );
    println!("  Known since:        {}", known_since(record));
    if let Some(value) = &record.dates.filesystem_created_at {
        println!(
            "  Install estimate:   {} ({}, {})",
            value
                .value
                .map(|date| date.to_rfc3339())
                .unwrap_or_else(|| "Unknown".into()),
            value.source,
            confidence_label(value.confidence)
        );
    }
    println!(
        "  Owned size:         {} ({}, {})",
        size_label(record.sizes.owned_allocated_bytes),
        record.sizes.method,
        confidence_label(record.sizes.confidence)
    );
    println!("  Commands:");
    for command in snapshot
        .commands
        .iter()
        .filter(|command| command.owner_installation_id == record.id)
    {
        println!(
            "    {} -> {} [{:?}; PATH rank {}]",
            command.name,
            command.path,
            command.exposure_state,
            command
                .path_rank
                .map(|rank| rank.to_string())
                .unwrap_or_else(|| "not on PATH".into())
        );
    }
    println!("  Findings:");
    for finding in snapshot
        .findings
        .iter()
        .filter(|finding| finding.installation_ids.contains(&record.id))
    {
        println!(
            "    [{}] {} — {}",
            severity_label(finding.severity),
            finding.code,
            finding.explanation
        );
    }
    if record.finding_ids.is_empty() {
        println!("    None");
    }
    Ok(())
}

pub fn metadata_text<'a>(record: &'a InstallationRecord, key: &str) -> Option<&'a str> {
    record.metadata.get(key).and_then(serde_json::Value::as_str)
}

pub fn findings(snapshot: &Snapshot, findings: &[&Finding], format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => {
            return json(&serde_json::json!({
                "schema_version": snapshot.schema_version,
                "generated_at": snapshot.generated_at,
                "scan_id": snapshot.scan_id,
                "partial": snapshot.partial,
                "findings": findings
            }));
        }
        OutputFormat::Jsonl => {
            let mut output = io::stdout().lock();
            for finding in findings {
                write_jsonl(&mut output, snapshot, "finding", finding)?;
            }
            return Ok(());
        }
        OutputFormat::Csv => {
            let mut writer = csv::Writer::from_writer(io::stdout().lock());
            writer.write_record([
                "id",
                "severity",
                "code",
                "confidence",
                "title",
                "explanation",
                "installation_ids",
                "command_ids",
            ])?;
            for finding in findings {
                writer.write_record([
                    finding.id.as_str(),
                    severity_label(finding.severity),
                    finding.code.as_str(),
                    confidence_label(finding.confidence),
                    finding.title.as_str(),
                    finding.explanation.as_str(),
                    &finding.installation_ids.join(";"),
                    &finding.command_ids.join(";"),
                ])?;
            }
            writer.flush()?;
            return Ok(());
        }
        OutputFormat::Table => {}
    }
    println!("SEVERITY  CODE                  TITLE");
    for finding in findings {
        println!(
            "{} {} {}",
            colored_severity(&pad(severity_label(finding.severity), 9), finding.severity),
            pad(&finding.code, 21),
            finding.title
        );
    }
    if findings.is_empty() {
        println!("No matching findings.");
    }
    Ok(())
}

pub fn audit(snapshot: &Snapshot, format: OutputFormat) -> Result<()> {
    if format == OutputFormat::Json {
        return json(snapshot);
    }
    let counts = [
        Severity::Critical,
        Severity::Warning,
        Severity::Review,
        Severity::Info,
    ];
    println!("pkgscope audit — scan {}", snapshot.scan_id);
    println!("  Installations: {}", snapshot.installations.len());
    println!("  Commands:      {}", snapshot.commands.len());
    println!("  Managers:      {}", snapshot.manager_instances.len());
    println!("  Partial:       {}", snapshot.partial);
    for severity in counts {
        println!(
            "  {} {}",
            colored_severity(&pad(severity_label(severity), 13), severity),
            snapshot
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .count()
        );
    }
    if !snapshot.errors.is_empty() {
        println!("  Scanner errors:");
        for error in &snapshot.errors {
            println!("    {} [{}] {}", error.manager, error.code, error.message);
        }
    }
    Ok(())
}

fn colored_severity(value: &str, severity: Severity) -> String {
    if !color_enabled() {
        return value.into();
    }
    let code = match severity {
        Severity::Critical => 31,
        Severity::Warning => 33,
        Severity::Review => 36,
        Severity::Info => 34,
    };
    format!("\x1b[{code}m{value}\x1b[0m")
}

pub fn removal_plan(plan: &RemovalPlan, json_format: bool) -> Result<()> {
    if json_format {
        return json(plan);
    }
    println!("Removal plan (read-only; nothing will be executed)");
    println!(
        "  Target:       {} {}",
        plan.target_name,
        plan.target_version.as_deref().unwrap_or("Unknown")
    );
    println!("  Installation: {}", plan.installation_id);
    println!(
        "  Action argv:  {}",
        std::iter::once(plan.action.executable.as_str())
            .chain(plan.action.argv.iter().map(String::as_str))
            .map(shell_quote)
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "  Dependents:   {}",
        if plan.managed_dependents.is_empty() {
            "None reported by this manager".into()
        } else {
            plan.managed_dependents.join(", ")
        }
    );
    for warning in &plan.warnings {
        println!("  Warning:      {warning}");
    }
    if !plan.related_data_excluded.is_empty() {
        println!("  Related data not included:");
        for path in &plan.related_data_excluded {
            println!("    {path}");
        }
    }
    println!("  Rollback:     not promised");
    Ok(())
}

pub fn size_label(bytes: Option<u64>) -> String {
    let Some(bytes) = bytes else {
        return "Unknown".into();
    };
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn sort_records(
    records: &mut Vec<&InstallationRecord>,
    sort: SortField,
    order: SortOrder,
    snapshot: &Snapshot,
) {
    records.sort_by(|a, b| {
        let ordering = match sort {
            SortField::Name => a.identity.name.cmp(&b.identity.name),
            SortField::Manager => manager_for(snapshot, a)
                .map(|value| value.manager)
                .cmp(&manager_for(snapshot, b).map(|value| value.manager)),
            SortField::Environment => a.environment.cmp(&b.environment),
            SortField::Version => a.version.value.cmp(&b.version.value),
            SortField::Size => a
                .sizes
                .owned_allocated_bytes
                .cmp(&b.sizes.owned_allocated_bytes),
            SortField::KnownSince => install_date_value(a).cmp(&install_date_value(b)),
            SortField::Findings => max_severity(snapshot, a).cmp(&max_severity(snapshot, b)),
        }
        .then_with(|| a.id.cmp(&b.id));
        if order == SortOrder::Desc {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

pub fn manager_for<'a>(
    snapshot: &'a Snapshot,
    record: &InstallationRecord,
) -> Option<&'a ManagerInstance> {
    snapshot
        .manager_instances
        .iter()
        .find(|instance| instance.id == record.manager_instance_id)
}

pub fn max_severity(snapshot: &Snapshot, record: &InstallationRecord) -> Option<Severity> {
    snapshot
        .findings
        .iter()
        .filter(|finding| finding.installation_ids.contains(&record.id))
        .map(|finding| finding.severity)
        .max()
}

pub fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "INFO",
        Severity::Review => "REVIEW",
        Severity::Warning => "WARNING",
        Severity::Critical => "CRITICAL",
    }
}

pub fn finding_codes(snapshot: &Snapshot, record: &InstallationRecord) -> String {
    let mut codes: Vec<_> = snapshot
        .findings
        .iter()
        .filter(|finding| finding.installation_ids.contains(&record.id))
        .map(|finding| finding.code.as_str())
        .collect();
    codes.sort();
    codes.dedup();
    if codes.is_empty() {
        "-".into()
    } else {
        codes.join(",")
    }
}

fn known_since(record: &InstallationRecord) -> String {
    known_since_value(record)
        .map(|value| value.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "Unknown".into())
}

pub(crate) fn install_date_label(record: &InstallationRecord) -> String {
    install_date_value(record)
        .map(|value| value.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "Unknown".into())
}

/// Best locally available approximation of when this installed version appeared.
/// Manager-reported timestamps are preferred; filesystem and first-observation
/// timestamps are explicit fallbacks because many managers do not retain install history.
pub(crate) fn install_date_value(
    record: &InstallationRecord,
) -> Option<chrono::DateTime<chrono::Utc>> {
    [
        record.dates.current_version_installed_at.as_ref(),
        record.dates.manager_install_event_at.as_ref(),
        record.dates.filesystem_created_at.as_ref(),
        record.dates.first_seen_at.as_ref(),
    ]
    .into_iter()
    .flatten()
    .find_map(|field| field.value)
}

fn known_since_value(record: &InstallationRecord) -> Option<chrono::DateTime<chrono::Utc>> {
    record
        .dates
        .first_seen_at
        .as_ref()
        .and_then(|value| value.value)
}

fn confidence_label(confidence: crate::model::Confidence) -> &'static str {
    match confidence {
        crate::model::Confidence::Exact => "exact",
        crate::model::Confidence::High => "high confidence",
        crate::model::Confidence::Estimated => "estimated",
        crate::model::Confidence::Ambiguous => "ambiguous",
        crate::model::Confidence::Unknown => "unknown",
    }
}

fn terminal_width() -> usize {
    crossterm::terminal::size()
        .map(|(width, _)| usize::from(width))
        .ok()
        .or_else(|| std::env::var("COLUMNS").ok()?.parse().ok())
        .unwrap_or(120)
}

pub fn truncate(value: &str, width: usize) -> String {
    if UnicodeWidthStr::width(value) <= width {
        return value.to_string();
    }
    if width == 0 {
        return String::new();
    }
    if width == 1 {
        return "…".into();
    }
    let mut output = String::new();
    let target = width - 1;
    let mut used = 0;
    for grapheme in value.graphemes(true) {
        let grapheme_width = UnicodeWidthStr::width(grapheme);
        if used + grapheme_width > target {
            break;
        }
        output.push_str(grapheme);
        used += grapheme_width;
    }
    output.push('…');
    output
}

fn pad(value: &str, width: usize) -> String {
    let value = truncate(value, width);
    let padding = width.saturating_sub(UnicodeWidthStr::width(value.as_str()));
    format!("{value}{}", " ".repeat(padding))
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_+-./:@%=".contains(&byte))
    {
        value.into()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_respects_cjk_width() {
        assert_eq!(truncate("日本語tool", 7), "日本語…");
        assert_eq!(
            UnicodeWidthStr::width(truncate("日本語tool", 7).as_str()),
            7
        );
        assert_eq!(truncate("👨‍👩‍👧‍👦abc", 3), "👨‍👩‍👧‍👦…");
    }

    #[test]
    fn human_sizes_do_not_imply_unknown_values() {
        assert_eq!(size_label(None), "Unknown");
        assert_eq!(size_label(Some(1_500_000)), "1.5 MB");
    }
}
