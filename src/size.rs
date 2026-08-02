use std::{collections::HashSet, path::Path};

use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, Default)]
pub struct SizeMeasurement {
    pub apparent_bytes: u64,
    pub allocated_bytes: u64,
    pub files: u64,
    pub incomplete: bool,
}

pub fn measure_owned(root: &Path, max_entries: usize) -> SizeMeasurement {
    let mut result = SizeMeasurement::default();
    let mut seen = HashSet::new();
    for (index, entry) in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index >= max_entries {
            result.incomplete = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                result.incomplete = true;
                continue;
            }
        };
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                result.incomplete = true;
                continue;
            }
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !seen.insert((metadata.dev(), metadata.ino())) {
                continue;
            }
            result.allocated_bytes = result
                .allocated_bytes
                .saturating_add(metadata.blocks().saturating_mul(512));
        }
        result.apparent_bytes = result.apparent_bytes.saturating_add(metadata.len());
        result.files += 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use super::*;

    #[test]
    fn symlink_targets_are_not_double_counted() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("data");
        fs::File::create(&path)
            .unwrap()
            .write_all(b"12345")
            .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&path, temp.path().join("link")).unwrap();
        let measured = measure_owned(temp.path(), 100);
        assert_eq!(measured.apparent_bytes, 5);
    }
}
