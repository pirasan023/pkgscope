use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};

use crate::model::{Confidence, FieldValue, Snapshot};

const DB_SCHEMA_VERSION: i64 = 2;
const DEFAULT_MAX_SNAPSHOTS: u32 = 20;
const DEFAULT_MAX_AGE_DAYS: u32 = 30;

pub struct StateStore {
    connection: Connection,
    path: PathBuf,
    max_snapshots: i64,
    max_age_days: u32,
}

impl StateStore {
    pub fn open_default() -> Result<Self> {
        Self::open_default_with_policy(DEFAULT_MAX_SNAPSHOTS, DEFAULT_MAX_AGE_DAYS)
    }

    pub fn open_default_with_policy(max_snapshots: u32, max_age_days: u32) -> Result<Self> {
        let path = default_state_path()?;
        migrate_legacy_state(&path)?;
        Self::open_with_policy(&path, max_snapshots, max_age_days)
    }

    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_policy(path, DEFAULT_MAX_SNAPSHOTS, DEFAULT_MAX_AGE_DAYS)
    }

    fn open_with_policy(path: &Path, max_snapshots: u32, max_age_days: u32) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("could not create state directory {}", parent.display())
            })?;
            set_user_only_permissions(parent)?;
        }
        match Self::open_inner(path, max_snapshots, max_age_days) {
            Ok(store) => Ok(store),
            Err(first_error) if path.exists() && is_database_corruption(&first_error) => {
                let recovery =
                    path.with_extension(format!("corrupt-{}", Utc::now().format("%Y%m%dT%H%M%SZ")));
                preserve_database(path, &recovery).with_context(|| {
                    format!(
                        "state database was unhealthy ({first_error:#}) and could not be moved to {}",
                        recovery.display()
                    )
                })?;
                eprintln!(
                    "warning: the state database was unhealthy and was preserved at {}; starting with a clean state",
                    crate::sanitize::terminal_text(&recovery.display().to_string())
                );
                Self::open_inner(path, max_snapshots, max_age_days)
            }
            Err(error) => Err(error),
        }
    }

    fn open_inner(path: &Path, max_snapshots: u32, max_age_days: u32) -> Result<Self> {
        let connection = Connection::open(path)
            .with_context(|| format!("could not open state database {}", path.display()))?;
        set_user_file_permissions(path)?;
        connection.busy_timeout(Duration::from_secs(2))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS metadata (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshots (
              scan_id TEXT PRIMARY KEY,
              generated_at TEXT NOT NULL,
              partial INTEGER NOT NULL,
              document TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS snapshots_generated_at
              ON snapshots(generated_at DESC);
            CREATE TABLE IF NOT EXISTS sightings (
              installation_id TEXT PRIMARY KEY,
              first_seen_at TEXT NOT NULL,
              last_seen_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS finding_sightings (
              finding_id TEXT PRIMARY KEY,
              first_seen_at TEXT NOT NULL,
              last_seen_at TEXT NOT NULL
            );
            ",
        )?;
        let stored_version: Option<i64> = connection
            .query_row(
                "SELECT CAST(value AS INTEGER) FROM metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if stored_version.is_some_and(|version| version > DB_SCHEMA_VERSION) {
            anyhow::bail!(
                "state database schema {} is newer than this pkgscope supports ({})",
                stored_version.unwrap_or_default(),
                DB_SCHEMA_VERSION
            );
        }
        connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('schema_version', ?1)",
            [DB_SCHEMA_VERSION.to_string()],
        )?;
        let health: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if health != "ok" {
            anyhow::bail!("SQLite quick_check returned {health}");
        }
        Ok(Self {
            connection,
            path: path.to_path_buf(),
            max_snapshots: i64::from(max_snapshots),
            max_age_days,
        })
    }

    pub fn latest(&self) -> Result<Option<Snapshot>> {
        let document: Option<String> = self
            .connection
            .query_row(
                "SELECT document FROM snapshots ORDER BY generated_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        document
            .map(|document| {
                serde_json::from_str(&document).context("latest snapshot could not be decoded")
            })
            .transpose()
    }

    pub fn save(&mut self, snapshot: &mut Snapshot) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .context("another pkgscope process is writing the state database")?;
        let now = snapshot.generated_at;
        for installation in &mut snapshot.installations {
            let first: Option<String> = transaction
                .query_row(
                    "SELECT first_seen_at FROM sightings WHERE installation_id=?1",
                    [&installation.id],
                    |row| row.get(0),
                )
                .optional()?;
            let first_seen = first
                .as_deref()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc))
                .unwrap_or(now);
            transaction.execute(
                "INSERT INTO sightings(installation_id, first_seen_at, last_seen_at)
                 VALUES(?1, ?2, ?3)
                 ON CONFLICT(installation_id) DO UPDATE SET last_seen_at=excluded.last_seen_at",
                params![installation.id, first_seen.to_rfc3339(), now.to_rfc3339()],
            )?;
            installation.dates.first_seen_at = Some(FieldValue {
                value: Some(first_seen),
                source: "pkgscope_snapshot_store".into(),
                confidence: Confidence::Exact,
                observed_at: now,
            });
            installation.dates.last_seen_at = Some(FieldValue {
                value: Some(now),
                source: "pkgscope_snapshot_store".into(),
                confidence: Confidence::Exact,
                observed_at: now,
            });
        }
        for finding in &mut snapshot.findings {
            let first: Option<String> = transaction
                .query_row(
                    "SELECT first_seen_at FROM finding_sightings WHERE finding_id=?1",
                    [&finding.id],
                    |row| row.get(0),
                )
                .optional()?;
            let first_seen = first
                .as_deref()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc))
                .unwrap_or(now);
            transaction.execute(
                "INSERT INTO finding_sightings(finding_id, first_seen_at, last_seen_at)
                 VALUES(?1, ?2, ?3)
                 ON CONFLICT(finding_id) DO UPDATE SET last_seen_at=excluded.last_seen_at",
                params![finding.id, first_seen.to_rfc3339(), now.to_rfc3339()],
            )?;
            finding.first_seen_at = first_seen;
            finding.last_seen_at = now;
        }
        let document = serde_json::to_string(snapshot)?;
        transaction.execute(
            "INSERT OR REPLACE INTO snapshots(scan_id, generated_at, partial, document)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                snapshot.scan_id,
                snapshot.generated_at.to_rfc3339(),
                snapshot.partial,
                document
            ],
        )?;
        transaction.execute(
            "DELETE FROM snapshots WHERE scan_id IN (
               SELECT scan_id FROM snapshots ORDER BY generated_at DESC LIMIT -1 OFFSET ?1
             )",
            [self.max_snapshots],
        )?;
        let cutoff = now - chrono::Duration::days(i64::from(self.max_age_days));
        transaction.execute(
            "DELETE FROM snapshots WHERE generated_at < ?1",
            [cutoff.to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn health(&self) -> Result<String> {
        self.connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .context("state health check failed")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn is_database_corruption(error: &anyhow::Error) -> bool {
    if error.to_string().contains("SQLite quick_check returned") {
        return true;
    }
    error.chain().any(|cause| {
        cause
            .downcast_ref::<rusqlite::Error>()
            .is_some_and(|error| match error {
                rusqlite::Error::SqliteFailure(details, _) => matches!(
                    details.code,
                    rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
                ),
                _ => false,
            })
    })
}

fn migrate_legacy_state(destination: &Path) -> Result<()> {
    if destination.exists() {
        return Ok(());
    }
    let Some(legacy_base) = dirs::data_local_dir() else {
        return Ok(());
    };
    let legacy = legacy_base.join("pkgscope/state.db");
    if legacy == destination || !legacy.exists() {
        return Ok(());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
        set_user_only_permissions(parent)?;
    }
    fs::rename(&legacy, destination).with_context(|| {
        format!(
            "could not migrate state from {} to {}",
            legacy.display(),
            destination.display()
        )
    })?;
    for suffix in ["-wal", "-shm"] {
        let old = PathBuf::from(format!("{}{}", legacy.display(), suffix));
        if old.exists() {
            let new = PathBuf::from(format!("{}{}", destination.display(), suffix));
            let _ = fs::rename(old, new);
        }
    }
    Ok(())
}

pub fn default_state_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".local/share")))
        .context("could not determine the user data directory")?;
    Ok(base.join("pkgscope/state.db"))
}

pub fn reset() -> Result<Option<PathBuf>> {
    let path = default_state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let backup = path.with_extension(format!("reset-{}", Utc::now().format("%Y%m%dT%H%M%SZ")));
    preserve_database(&path, &backup)
        .with_context(|| format!("could not preserve old state at {}", backup.display()))?;
    Ok(Some(backup))
}

fn preserve_database(path: &Path, backup: &Path) -> Result<()> {
    fs::rename(path, backup)?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        if sidecar.exists() {
            fs::rename(
                &sidecar,
                PathBuf::from(format!("{}{}", backup.display(), suffix)),
            )?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_user_only_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(unix)]
fn set_user_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_only_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_user_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, Finding, ScanScope, Severity};

    #[test]
    fn snapshot_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = StateStore::open(&temp.path().join("state.db")).unwrap();
        let mut snapshot = Snapshot::empty(ScanScope::default());
        store.save(&mut snapshot).unwrap();
        assert_eq!(store.latest().unwrap().unwrap().scan_id, snapshot.scan_id);
        assert_eq!(store.health().unwrap(), "ok");
    }

    #[test]
    fn finding_first_seen_survives_and_snapshot_retention_is_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            StateStore::open_with_policy(&temp.path().join("state.db"), 1, 3_650).unwrap();
        let mut first = Snapshot::empty(ScanScope::default());
        first
            .findings
            .push(test_finding("same", first.generated_at));
        store.save(&mut first).unwrap();
        let original_first_seen = first.findings[0].first_seen_at;

        let mut second = Snapshot::empty(ScanScope::default());
        second.generated_at = first.generated_at + chrono::Duration::seconds(1);
        second
            .findings
            .push(test_finding("same", second.generated_at));
        store.save(&mut second).unwrap();

        assert_eq!(second.findings[0].first_seen_at, original_first_seen);
        let count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM snapshots", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn database_preservation_moves_sidecars_together() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        let backup = temp.path().join("state.backup");
        fs::write(&path, "database").unwrap();
        fs::write(PathBuf::from(format!("{}-wal", path.display())), "wal").unwrap();

        preserve_database(&path, &backup).unwrap();

        assert!(backup.exists());
        assert!(PathBuf::from(format!("{}-wal", backup.display())).exists());
        assert!(!path.exists());
    }

    #[test]
    fn corrupt_database_is_preserved_before_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state.db");
        fs::write(&path, "not a sqlite database").unwrap();

        let store = StateStore::open(&path).unwrap();

        assert_eq!(store.health().unwrap(), "ok");
        assert!(fs::read_dir(temp.path()).unwrap().flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("state.corrupt-")
        }));
    }

    fn test_finding(id: &str, observed_at: DateTime<Utc>) -> Finding {
        Finding {
            id: id.into(),
            code: "test".into(),
            severity: Severity::Review,
            confidence: Confidence::Exact,
            installation_ids: Vec::new(),
            command_ids: Vec::new(),
            title: "test".into(),
            explanation: "test".into(),
            evidence_refs: Vec::new(),
            suggested_action: None,
            first_seen_at: observed_at,
            last_seen_at: observed_at,
        }
    }
}
