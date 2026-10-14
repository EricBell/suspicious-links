use crate::reporter::{write_report_to_dir, ReportEntry};
use crate::sanitizer::{sanitize_file, SanitizeResult};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub root_path: PathBuf,
    pub recursive: bool,
    pub replacement_token: String,
    pub report_filename: String,
    pub include_gfm_delimiter: bool,
    pub backup: bool,
    pub dry_run: bool,
    pub include_hidden: bool,
    pub verbose: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            root_path: PathBuf::from("."),
            recursive: true,
            replacement_token: "[Suspicious Link Removed]".to_string(),
            report_filename: "suspicious-links.md".to_string(),
            include_gfm_delimiter: false,
            backup: false,
            dry_run: false,
            include_hidden: false,
            verbose: false,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub files_modified: usize,
    pub files_skipped_binary: usize,
    pub total_links_replaced: usize,
    pub reports_generated: Vec<PathBuf>,
}

/// Walks `config.root_path` and returns the files eligible for scanning:
/// skips `.git`, hidden entries (unless requested), the report file and `.bak` files.
fn collect_files(config: &ScannerConfig) -> Vec<PathBuf> {
    let root = &config.root_path;
    let mut walk = WalkDir::new(root);
    if !config.recursive && root.is_dir() {
        walk = walk.max_depth(1);
    }

    let report_lower = config.report_filename.to_lowercase();
    let mut files = Vec::new();

    for entry in walk.into_iter().filter_entry(|e| {
        let file_name = e.file_name().to_string_lossy();
        if file_name == ".git" {
            return false;
        }
        if !config.include_hidden && file_name.starts_with('.') && e.depth() > 0 {
            return false;
        }
        true
    }) {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                if config.verbose {
                    eprintln!("Warning: skipping unreadable entry: {}", err);
                }
                continue;
            }
        };

        if !entry.path().is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy();
        // Skip any existing report file (case-insensitive) to prevent recursive self-modification
        if file_name.to_lowercase() == report_lower || file_name.ends_with(".bak") {
            continue;
        }

        files.push(entry.into_path());
    }

    files
}

/// A previously inserted marker found in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundMarker {
    pub path: PathBuf,
    pub value: String,
}

/// Text searched for by `find_markers` (matched case-insensitively).
pub const MARKER_TEXT: &str = "Suspicious Link Removed";

/// Read-only scan for occurrences of `MARKER_TEXT`, in file and textual order.
/// Binary and non-UTF-8 files are skipped; nothing is modified.
pub fn find_markers(config: &ScannerConfig) -> io::Result<Vec<FoundMarker>> {
    if !config.root_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Path '{}' does not exist", config.root_path.display()),
        ));
    }

    let needle = MARKER_TEXT.to_lowercase();
    let mut found = Vec::new();

    for path in collect_files(config) {
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => continue,
            Err(e) => return Err(e),
        };
        if content.contains('\0') {
            continue;
        }
        // ASCII lowercasing keeps byte offsets identical to the original text.
        let lower = content.to_ascii_lowercase();
        for (idx, _) in lower.match_indices(&needle) {
            found.push(FoundMarker {
                path: path.clone(),
                value: content[idx..idx + needle.len()].to_string(),
            });
        }
    }

    Ok(found)
}

pub fn run_scanner(config: &ScannerConfig) -> io::Result<ScanSummary> {
    let mut summary = ScanSummary::default();
    let mut dir_entries_map: BTreeMap<PathBuf, Vec<ReportEntry>> = BTreeMap::new();

    let root = &config.root_path;
    if !root.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("Path '{}' does not exist", root.display()),
        ));
    }

    for path in collect_files(config) {
        let path = path.as_path();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        summary.files_scanned += 1;
        if config.verbose {
            eprintln!("Scanning: {}", path.display());
        }

        match sanitize_file(
            path,
            &config.replacement_token,
            config.backup,
            config.dry_run,
        )? {
            SanitizeResult::SkippedBinary => {
                summary.files_skipped_binary += 1;
                if config.verbose {
                    eprintln!("  Skipped binary file: {}", path.display());
                }
            }
            SanitizeResult::Unmodified => {
                // No links found, nothing to do
            }
            SanitizeResult::Modified { links, backup_path } => {
                summary.files_modified += 1;
                summary.total_links_replaced += links.len();

                if config.verbose {
                    eprintln!(
                        "  Replaced {} link(s) in {}",
                        links.len(),
                        path.display()
                    );
                    if let Some(bak) = backup_path {
                        eprintln!("  Created backup at: {}", bak.display());
                    }
                }

                let parent_dir = path
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("."));

                let entries = dir_entries_map.entry(parent_dir).or_default();
                for link in links {
                    entries.push(ReportEntry {
                        file_name: file_name.to_string(),
                        link: link.original_link,
                    });
                }
            }
        }
    }

    // Write reports in each directory where files were modified
    for (dir, entries) in dir_entries_map {
        if !config.dry_run {
            let report_path = write_report_to_dir(
                &dir,
                &config.report_filename,
                &entries,
                config.include_gfm_delimiter,
            )?;
            summary.reports_generated.push(report_path);
        } else {
            summary.reports_generated.push(dir.join(&config.report_filename));
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_user_scenario_water_field() {
        // Reproduce exact user scenario:
        // directory water/field with north.txt and south.txt
        let root = tempdir().unwrap();
        let field_dir = root.path().join("water").join("field");
        fs::create_dir_all(&field_dir).unwrap();

        let north_txt = field_dir.join("north.txt");
        let south_txt = field_dir.join("south.txt");

        fs::write(
            &north_txt,
            "Body of text with 2 links, one to email mail://eric@ericbell.net and a weblink https://polymorph.co.",
        )
        .unwrap();

        fs::write(
            &south_txt,
            "South file has clean content without any links.",
        )
        .unwrap();

        let config = ScannerConfig {
            root_path: root.path().to_path_buf(),
            recursive: true,
            replacement_token: "[Suspicious Link Removed]".to_string(),
            report_filename: "suspicious-links.md".to_string(),
            include_gfm_delimiter: false,
            backup: false,
            dry_run: false,
            include_hidden: false,
            verbose: false,
        };

        let summary = run_scanner(&config).unwrap();

        assert_eq!(summary.files_scanned, 2);
        assert_eq!(summary.files_modified, 1);
        assert_eq!(summary.total_links_replaced, 2);
        assert_eq!(summary.reports_generated.len(), 1);

        // Verify north.txt content
        let north_content = fs::read_to_string(&north_txt).unwrap();
        assert_eq!(
            north_content,
            "Body of text with 2 links, one to email [Suspicious Link Removed] and a weblink [Suspicious Link Removed]."
        );

        // Verify south.txt untouched
        let south_content = fs::read_to_string(&south_txt).unwrap();
        assert_eq!(south_content, "South file has clean content without any links.");

        // Verify suspicious-links.md generated inside water/field/
        let report_file = field_dir.join("suspicious-links.md");
        assert!(report_file.exists());
        let report_content = fs::read_to_string(&report_file).unwrap();
        let expected_report = "| file | link |\n\
                               |north.txt | mail://eric@ericbell.net|\n\
                               |north.txt | https://polymorph.co|\n";
        assert_eq!(report_content, expected_report);
    }
}
