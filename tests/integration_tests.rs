use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn get_bin_path() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Pop test name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("suspicious-links");
    path
}

#[test]
fn test_cli_exact_user_specification() {
    let root = tempdir().unwrap();
    let field_dir = root.path().join("water").join("field");
    fs::create_dir_all(&field_dir).unwrap();

    let north_file = field_dir.join("north.txt");
    let south_file = field_dir.join("south.txt");

    fs::write(
        &north_file,
        "in north.txt there is a body of text with 2 links, one to email mail://eric@ericbell.net and a weblink https://polymorph.co. This is a test.",
    ).unwrap();

    fs::write(
        &south_file,
        "south.txt contains purely benign text with zero links.",
    ).unwrap();

    let bin = get_bin_path();
    let output = Command::new(&bin)
        .arg(&field_dir)
        .output()
        .expect("Failed to execute suspicious-links binary");

    assert!(output.status.success(), "CLI failed with: {:?}", output);

    // Verify north.txt content
    let north_content = fs::read_to_string(&north_file).unwrap();
    assert_eq!(
        north_content,
        "in north.txt there is a body of text with 2 links, one to email [Suspicious Link Removed] and a weblink [Suspicious Link Removed]. This is a test."
    );

    // Verify south.txt is untouched
    let south_content = fs::read_to_string(&south_file).unwrap();
    assert_eq!(
        south_content,
        "south.txt contains purely benign text with zero links."
    );

    // Verify suspicious-links.md in water/field/
    let report_file = field_dir.join("suspicious-links.md");
    assert!(report_file.exists());
    let report_content = fs::read_to_string(&report_file).unwrap();
    let expected_report = "| file | link |\n\
                           |north.txt | mail://eric@ericbell.net|\n\
                           |north.txt | https://polymorph.co|\n";
    assert_eq!(report_content, expected_report);
}

#[test]
fn test_cli_multiple_subdirectories_and_isolation() {
    let root = tempdir().unwrap();
    let dir_a = root.path().join("folder_a");
    let dir_b = root.path().join("folder_b");
    let dir_clean = root.path().join("folder_clean");

    fs::create_dir_all(&dir_a).unwrap();
    fs::create_dir_all(&dir_b).unwrap();
    fs::create_dir_all(&dir_clean).unwrap();

    fs::write(
        dir_a.join("a.txt"),
        "Link in A: https://example.a.com",
    ).unwrap();

    fs::write(
        dir_b.join("b.txt"),
        "Link in B: mail://b@example.b.com",
    ).unwrap();

    fs::write(
        dir_clean.join("c.txt"),
        "No links here at all.",
    ).unwrap();

    let bin = get_bin_path();
    let output = Command::new(&bin)
        .arg(root.path())
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    // Report in dir_a
    let rep_a = dir_a.join("suspicious-links.md");
    assert!(rep_a.exists());
    assert_eq!(
        fs::read_to_string(&rep_a).unwrap(),
        "| file | link |\n|a.txt | https://example.a.com|\n"
    );

    // Report in dir_b
    let rep_b = dir_b.join("suspicious-links.md");
    assert!(rep_b.exists());
    assert_eq!(
        fs::read_to_string(&rep_b).unwrap(),
        "| file | link |\n|b.txt | mail://b@example.b.com|\n"
    );

    // No report in dir_clean
    let rep_clean = dir_clean.join("suspicious-links.md");
    assert!(!rep_clean.exists());

    // No report in root itself (since no direct files in root were modified)
    let rep_root = root.path().join("suspicious-links.md");
    assert!(!rep_root.exists());
}

#[test]
fn test_cli_dry_run() {
    let root = tempdir().unwrap();
    let file = root.path().join("sample.txt");
    let orig = "Original https://example.com link";
    fs::write(&file, orig).unwrap();

    let bin = get_bin_path();
    let output = Command::new(&bin)
        .arg(root.path())
        .arg("--dry-run")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    // File must NOT be modified
    assert_eq!(fs::read_to_string(&file).unwrap(), orig);
    // Report must NOT be written to disk
    assert!(!root.path().join("suspicious-links.md").exists());
}

#[test]
fn test_cli_custom_replacement_and_backup() {
    let root = tempdir().unwrap();
    let file = root.path().join("sample.txt");
    let orig = "Visit https://example.com now";
    fs::write(&file, orig).unwrap();

    let bin = get_bin_path();
    let output = Command::new(&bin)
        .arg(root.path())
        .arg("--replacement")
        .arg("[REDACTED]")
        .arg("--backup")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    // Check replaced content
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "Visit [REDACTED] now"
    );

    // Check backup file exists
    let bak_file = root.path().join("sample.txt.bak");
    assert!(bak_file.exists());
    assert_eq!(fs::read_to_string(bak_file).unwrap(), orig);
}

#[test]
fn test_cli_idempotent_rerun() {
    let root = tempdir().unwrap();
    let file = root.path().join("sample.txt");
    fs::write(&file, "Link: https://example.com").unwrap();

    let bin = get_bin_path();

    // First run
    let out1 = Command::new(&bin)
        .arg(root.path())
        .output()
        .unwrap();
    assert!(out1.status.success());
    let report_content = fs::read_to_string(root.path().join("suspicious-links.md")).unwrap();

    // Second run
    let out2 = Command::new(&bin)
        .arg(root.path())
        .output()
        .unwrap();
    assert!(out2.status.success());

    // Output summary in stdout should report 0 files modified on second run
    let stdout = String::from_utf8_lossy(&out2.stdout);
    assert!(stdout.contains("Files modified:       0"));

    // Content of suspicious-links.md remains valid
    assert_eq!(
        fs::read_to_string(root.path().join("suspicious-links.md")).unwrap(),
        report_content
    );
}
