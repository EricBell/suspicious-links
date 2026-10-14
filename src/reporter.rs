use std::fs;
use std::io;
use std::path::Path;

/// Represents an entry in the suspicious links report
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportEntry {
    pub file_name: String,
    pub link: String,
}

/// Generates the markdown table string from entries.
/// Matches the exact specification:
/// | file | link |
/// |north.txt | mail://eric@ericbell.net|
/// |north.txt | https://polymorph.co|
pub fn generate_report(entries: &[ReportEntry], include_gfm_delimiter: bool) -> String {
    let mut out = String::new();
    out.push_str("| file | link |\n");
    if include_gfm_delimiter {
        out.push_str("| --- | --- |\n");
    }
    for entry in entries {
        out.push_str(&format!("|{} | {}|\n", entry.file_name, entry.link));
    }
    out
}

/// Writes or overwrites the `suspicious-links.md` report inside `directory`.
pub fn write_report_to_dir(
    directory: &Path,
    report_filename: &str,
    entries: &[ReportEntry],
    include_gfm_delimiter: bool,
) -> io::Result<std::path::PathBuf> {
    let report_path = directory.join(report_filename);
    let content = generate_report(entries, include_gfm_delimiter);
    fs::write(&report_path, content)?;
    Ok(report_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_report_matches_exact_user_spec() {
        let entries = vec![
            ReportEntry {
                file_name: "north.txt".to_string(),
                link: "mail://eric@ericbell.net".to_string(),
            },
            ReportEntry {
                file_name: "north.txt".to_string(),
                link: "https://polymorph.co".to_string(),
            },
        ];

        let report = generate_report(&entries, false);
        let expected = "| file | link |\n\
                        |north.txt | mail://eric@ericbell.net|\n\
                        |north.txt | https://polymorph.co|\n";
        assert_eq!(report, expected);
    }

    #[test]
    fn test_generate_report_gfm_delimiter() {
        let entries = vec![
            ReportEntry {
                file_name: "north.txt".to_string(),
                link: "https://polymorph.co".to_string(),
            },
        ];

        let report = generate_report(&entries, true);
        let expected = "| file | link |\n\
                        | --- | --- |\n\
                        |north.txt | https://polymorph.co|\n";
        assert_eq!(report, expected);
    }
}
