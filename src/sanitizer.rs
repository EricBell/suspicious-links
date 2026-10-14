use crate::detector::{replace_links, DetectedLink};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
pub enum SanitizeResult {
    /// File was binary or could not be decoded as UTF-8, so skipped
    SkippedBinary,
    /// File had no links, left untouched
    Unmodified,
    /// File had links replaced
    Modified {
        links: Vec<DetectedLink>,
        backup_path: Option<PathBuf>,
    },
}

/// Checks if a slice of bytes looks like binary data.
pub fn is_binary_buffer(buffer: &[u8]) -> bool {
    // Check for null bytes which indicate binary data
    if buffer.contains(&0) {
        return true;
    }
    // Check if the initial chunk is valid UTF-8
    // Note: a chunk boundary could split a UTF-8 sequence, but std::str::from_utf8
    // returns Utf8Error with valid_up_to(). If valid_up_to is near the end, it's likely UTF-8.
    match std::str::from_utf8(buffer) {
        Ok(_) => false,
        Err(e) => {
            // If the error happens right at the end of the buffer (within 4 bytes), it might be a split char
            buffer.len() - e.valid_up_to() >= 4 || e.error_len().is_some()
        }
    }
}

/// Sanitizes a file in place if it contains links.
pub fn sanitize_file(
    path: &Path,
    replacement_token: &str,
    backup: bool,
    dry_run: bool,
) -> io::Result<SanitizeResult> {
    // 1. Read file to check size and content
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Ok(SanitizeResult::Unmodified);
    }

    // Read first 8KB to check if binary
    let mut file = File::open(path)?;
    let mut sample = vec![0u8; 8192.min(metadata.len() as usize)];
    let bytes_read = file.read(&mut sample)?;
    sample.truncate(bytes_read);

    if is_binary_buffer(&sample) {
        return Ok(SanitizeResult::SkippedBinary);
    }

    // 2. Read full content as UTF-8
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            return Ok(SanitizeResult::SkippedBinary);
        }
        Err(e) => return Err(e),
    };

    // 3. Detect and replace links
    let (sanitized_content, detected_links) = replace_links(&content, replacement_token);

    if detected_links.is_empty() {
        return Ok(SanitizeResult::Unmodified);
    }

    if dry_run {
        return Ok(SanitizeResult::Modified {
            links: detected_links,
            backup_path: None,
        });
    }

    // 4. Handle backup if requested
    let mut backup_path = None;
    if backup {
        let bak = path.with_extension(format!(
            "{}.bak",
            path.extension().and_then(|s| s.to_str()).unwrap_or("")
        ));
        fs::copy(path, &bak)?;
        backup_path = Some(bak);
    }

    // 5. Atomic write: write to temp file in same directory, then rename
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".suspicious_links_tmp_")
        .tempfile_in(parent)?;

    temp.write_all(sanitized_content.as_bytes())?;
    temp.flush()?;

    // Persist atomically over original file
    temp.persist(path).map_err(|e| e.error)?;

    Ok(SanitizeResult::Modified {
        links: detected_links,
        backup_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_sanitize_file_modifies_links() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("north.txt");
        fs::write(
            &file_path,
            "mail mail://eric@ericbell.net and web https://polymorph.co",
        )
        .unwrap();

        let res = sanitize_file(&file_path, "[Suspicious Link Removed]", false, false).unwrap();

        match res {
            SanitizeResult::Modified { links, backup_path } => {
                assert_eq!(links.len(), 2);
                assert_eq!(links[0].original_link, "mail://eric@ericbell.net");
                assert_eq!(links[1].original_link, "https://polymorph.co");
                assert!(backup_path.is_none());
            }
            _ => panic!("Expected Modified"),
        }

        let new_content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(
            new_content,
            "mail [Suspicious Link Removed] and web [Suspicious Link Removed]"
        );
    }

    #[test]
    fn test_sanitize_file_unmodified() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("south.txt");
        fs::write(&file_path, "Clean text with no links whatsoever.").unwrap();

        let res = sanitize_file(&file_path, "[Suspicious Link Removed]", false, false).unwrap();
        assert_eq!(res, SanitizeResult::Unmodified);

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Clean text with no links whatsoever.");
    }

    #[test]
    fn test_sanitize_file_skips_binary() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("binary.bin");
        // write binary content with null bytes and a URL embedded
        let mut binary_data = vec![0u8, 159, 255, 0];
        binary_data.extend_from_slice(b"https://polymorph.co");
        binary_data.push(0);
        fs::write(&file_path, &binary_data).unwrap();

        let res = sanitize_file(&file_path, "[Suspicious Link Removed]", false, false).unwrap();
        assert_eq!(res, SanitizeResult::SkippedBinary);

        // Content remains untouched
        let read_back = fs::read(&file_path).unwrap();
        assert_eq!(read_back, binary_data);
    }

    #[test]
    fn test_dry_run_leaves_file_intact() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let orig = "Visit https://example.com today!";
        fs::write(&file_path, orig).unwrap();

        let res = sanitize_file(&file_path, "[Suspicious Link Removed]", false, true).unwrap();
        match res {
            SanitizeResult::Modified { links, .. } => {
                assert_eq!(links.len(), 1);
            }
            _ => panic!("Expected Modified in dry_run"),
        }

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, orig);
    }

    #[test]
    fn test_backup_creation() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let orig = "Visit https://example.com today!";
        fs::write(&file_path, orig).unwrap();

        let res = sanitize_file(&file_path, "[Suspicious Link Removed]", true, false).unwrap();
        match res {
            SanitizeResult::Modified { backup_path, .. } => {
                let bak = backup_path.expect("Backup path should exist");
                assert!(bak.exists());
                let bak_content = fs::read_to_string(bak).unwrap();
                assert_eq!(bak_content, orig);
            }
            _ => panic!("Expected Modified with backup"),
        }
    }
}
