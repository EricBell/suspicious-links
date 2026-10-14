use clap::Parser;
use std::path::PathBuf;
use std::process;
use suspicious_links::scanner::{run_scanner, ScannerConfig};

#[derive(Parser, Debug)]
#[command(
    name = "suspicious-links",
    author,
    version,
    about = "Scans files for hyperlinks and replaces them with [Suspicious Link Removed], generating suspicious-links.md mapping reports."
)]
struct Args {
    /// Directory or file to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Replacement token to substitute for detected links
    #[arg(short = 'r', long, default_value = "[Suspicious Link Removed]")]
    replacement: String,

    /// Name of the generated markdown mapping file
    #[arg(long, default_value = "suspicious-links.md")]
    report_name: String,

    /// Perform a dry run without modifying files or generating report files
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Create backup copies (.bak) of files before modifying them
    #[arg(short = 'b', long)]
    backup: bool,

    /// Do not recurse into subdirectories
    #[arg(long)]
    no_recurse: bool,

    /// Include hidden files and directories (names starting with .)
    #[arg(long)]
    include_hidden: bool,

    /// Include GitHub Flavored Markdown delimiter row (| --- | --- |) in the report
    #[arg(long)]
    gfm: bool,

    /// Print detailed progress information
    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    let config = ScannerConfig {
        root_path: args.path,
        recursive: !args.no_recurse,
        replacement_token: args.replacement,
        report_filename: args.report_name,
        include_gfm_delimiter: args.gfm,
        backup: args.backup,
        dry_run: args.dry_run,
        include_hidden: args.include_hidden,
        verbose: args.verbose,
    };

    if config.dry_run {
        println!("Running in DRY-RUN mode. No files will be modified.");
    }

    match run_scanner(&config) {
        Ok(summary) => {
            println!("----------------------------------------");
            println!("Scan Summary:");
            println!("  Files scanned:        {}", summary.files_scanned);
            println!("  Files skipped binary: {}", summary.files_skipped_binary);
            println!("  Files modified:       {}", summary.files_modified);
            println!("  Links replaced:       {}", summary.total_links_replaced);
            println!(
                "  Reports generated:    {}",
                summary.reports_generated.len()
            );

            for report in &summary.reports_generated {
                if config.dry_run {
                    println!("  [dry-run] Would generate report: {}", report.display());
                } else {
                    println!("  Generated report: {}", report.display());
                }
            }
            println!("----------------------------------------");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}
