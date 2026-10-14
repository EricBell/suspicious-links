# suspicious-links — Overview

> A Rust CLI for Debian Linux that scans files for hyperlinks, replaces each with `[Suspicious Link Removed]` in place, and writes a markdown mapping report per directory.

## Purpose

Neutralizes hyperlinks in text files (e.g. before sharing a document set) while keeping a record of what was removed. For every directory containing a modified file, it writes `suspicious-links.md`, a table of `file | link` rows in document order. Re-runs are idempotent: text already equal to the replacement token is not re-detected.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust (edition 2024), crate version 0.1.0 |
| CLI parsing | `clap` 4.5 (derive) |
| Link detection | `regex` 1.10 with `std::sync::LazyLock` statics |
| Directory walking | `walkdir` 2.5 |
| Atomic writes | `tempfile` 3.14 (a regular dependency, also used in tests) |
| Tests | Built-in `cargo test` (unit tests in `src/`, CLI tests in `tests/`) |

## Directory Structure

```
Cargo.toml / Cargo.lock
README.md              # user docs: flags, example
src/
  main.rs              # clap Args -> ScannerConfig, prints summary, exit 1 on error
  lib.rs               # exports detector, reporter, sanitizer, scanner
  scanner.rs           # walks the tree, orchestrates sanitizing + reports
  sanitizer.rs         # per-file: binary check, replace, backup, atomic write
  detector.rs          # regex link detection and replacement
  reporter.rs          # markdown table generation and writing
tests/
  integration_tests.rs # runs the compiled binary against temp dirs
```

## Architecture

The pipeline is: `main` → `scanner::run_scanner` → `sanitizer::sanitize_file` → `detector::replace_links`, then `reporter::write_report_to_dir`.

- **Scanner** (`src/scanner.rs`): uses `WalkDir`, pruning `.git` and, unless `--include-hidden`, dot-entries below the root (`depth() > 0`). It skips the report file (case-insensitive name match) and `*.bak` files. It collects `ReportEntry` rows in a `BTreeMap<PathBuf, Vec<ReportEntry>>` keyed by parent directory, then writes one report per directory after the walk. Reports are therefore local to each directory, not one global file. `--no-recurse` sets `max_depth(1)`.
- **Sanitizer** (`src/sanitizer.rs`): reads an 8 KB sample and treats the file as binary if it has a NUL byte or invalid UTF-8 (a tolerance for a multi-byte character split at the sample boundary). A full-file `read_to_string` that fails with `InvalidData` is also counted as binary. For modified files it optionally copies the original to a backup, then writes through a temp file `.suspicious_links_tmp_*` in the same directory and `persist`s it over the original. With `--dry-run` it returns `Modified` without writing anything.
- **Detector** (`src/detector.rs`): runs five regexes (Markdown `[t](url)`, HTML `href="…"`, `scheme://…`, `mailto:`, bare `www.`), collects candidates, sorts by start (longer span first), and drops any candidate overlapping an earlier accepted one. `trim_trailing_punctuation` strips sentence punctuation and unmatched `)`. Candidates equal to the replacement token are ignored, which gives idempotency.
- **Reporter** (`src/reporter.rs`): emits `| file | link |` and then `|name | link|` rows. This is a deliberately non-standard spacing format per the original spec. `--gfm` adds a `| --- | --- |` delimiter row.

## Integrations

None. There is no network access, database, or external service.

## Database & Data Layer

None. It is a stateless filesystem tool.

## Connectivity & Configuration

There are no environment variables. All configuration is via CLI flags (`[PATH]` defaults to `.`):

| Flag | Purpose |
|------|---------|
| `-r, --replacement` | Replacement token (default `[Suspicious Link Removed]`) |
| `--report-name` | Report filename (default `suspicious-links.md`) |
| `-n, --dry-run` | Don't modify files or write reports |
| `-b, --backup` | Write `.bak` copy before modifying |
| `--no-recurse` | Only scan the top directory |
| `--include-hidden` | Include dotfiles and dot-directories |
| `--gfm` | Add the GFM delimiter row to reports |
| `-v, --verbose` | Progress diagnostics to stderr |

## Key Entry Points

1. `src/main.rs`: argument parsing and the summary output.
2. `src/scanner.rs` (`run_scanner`): the main control flow.
3. `src/detector.rs` (`find_links`, `replace_links`): the core logic.
4. `tests/integration_tests.rs`: end-to-end behavior (exact spec, subdirectory isolation, dry run, custom replacement and backup, idempotent rerun).

## Notes & Gotchas

- **Report line format is intentionally odd**: `|north.txt | https://polymorph.co|`, with no space after the leading `|`. The unit and integration tests assert it exactly.
- **Idempotency is token-based.** `find_links` skips any candidate exactly equal to the replacement token, so a rerun doesn't re-detect it.
- **Backup naming** uses `path.with_extension("{ext}.bak")`, so `a.txt` becomes `a.txt.bak`. For an extensionless file the extension is empty, so the name is probably `name..bak` (not tested).
- **Reports are overwritten**, not appended, on each run. A second run finds no links, produces no entries, and leaves the earlier report untouched, so the original mapping persists only until another modification happens in that directory.
- **Plain markdown links are caught twice by design**: the URL inside `[t](url)` matches both the Markdown and scheme regexes, and the overlap resolver keeps one span.
- **Relative `href`/Markdown targets** (e.g. `local.html`, `docs/spec.html`) are treated as links and removed.
- **A single unreadable file aborts the scan**: `sanitize_file(...)?` propagates I/O errors, whereas unreadable directory entries are only warned about.
- `.gitignore` excludes `/target`, `*.bak`, and `suspicious-links.md`.
