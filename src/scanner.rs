use crate::reporter::{write_report_to_dir, ReportEntry};
use crate::sanitizer::{sanitize_file, SanitizeResult};
use std::collections::BTreeMap;
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

    let mut walk = WalkDir::new(root);
    if !config.recursive && root.is_dir() {
        walk = walk.max_depth(1);
    }

    let report_lower = config.report_filename.to_lowercase();

    for entry in walk
        .into_iter()
        .filter_entry(|e| {
            let file_name = e.file_name().to_string_lossy();
            // Skip .git directories
            if file_name == ".git" {
                return false;
            }
            // Skip hidden files/directories unless explicitly requested
            if !config.include_hidden && file_name.starts_with('.') && e.depth() > 0 {
                return false;
            }
            true
        })
    {
        let entry = match entry {
            Ok(e) => e,
            Err(err) => {
                if config.verbose {
                    eprintln!("Warning: skipping unreadable entry: {}", err);
                }
                continue;
            }
        };

        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy();

        // Skip any existing report file (case-insensitive) to prevent recursive self-modification
        if file_name.to_lowercase() == report_lower {
            continue;
        }

        // Skip backup files
        if file_name.ends_with(".bak") {
            continue;
        }

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
