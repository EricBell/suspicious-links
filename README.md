# suspicious-links

A fast and safe Rust CLI utility for Debian Linux that scans files in folders or directories for hyperlinks, neutralizes them by replacing each link with `[Suspicious Link Removed]`, and generates a markdown mapping log (`suspicious-links.md`) in each directory where files were modified.

---

## Features

- **Broad Link Detection:** Captures URI schemes (`https://`, `http://`, `mail://`, `mailto:`, `ftp://`, etc.), bare web addresses (`www.example.com`), HTML hyperlinks (`href="..."`), and Markdown link targets (`[anchor](url)`).
- **Exact Document Order:** Preserves chronological / textual order of links as they appear in source files.
- **Atomic File Writing:** Modifies files in-place using atomic replacement to prevent data corruption.
- **Directory-Local Mapping Reports:** Generates `suspicious-links.md` directly inside each directory where files were modified, matching the required markdown table format.
- **Binary & Safety Protection:** Skips binary files, `.git` metadata, and existing report files.
- **Configurable & Safe:** Includes `--dry-run`, `--backup` (`.bak`), `--replacement`, and `--report-name` flags.

---

## Installation & Build

Build the optimized release binary:

```bash
cargo build --release
```

The compiled binary will be located at:
`target/release/suspicious-links`

---

## Usage

### Basic Usage

Scan a directory recursively (defaults to current directory if omitted):

```bash
./target/release/suspicious-links /path/to/folder
```

Or run via Cargo:

```bash
cargo run -- /path/to/folder
```

### Dry Run (Preview Changes)

Inspect what would be modified without altering files or creating reports:

```bash
./target/release/suspicious-links /path/to/folder --dry-run
```

### Create Backups

Create `.bak` copies before modifying files:

```bash
./target/release/suspicious-links /path/to/folder --backup
```

### Custom Replacement Token

```bash
./target/release/suspicious-links /path/to/folder --replacement "[Suspicious Link Removed]"
```

### CLI Options

| Flag / Option | Short | Default | Description |
|---|---|---|---|
| `[PATH]` | | `.` | Target directory or file to scan |
| `--replacement` | `-r` | `[Suspicious Link Removed]` | Replacement token for detected links |
| `--report-name` | | `suspicious-links.md` | Name of generated report file |
| `--dry-run` | `-n` | `false` | Run without modifying files or creating reports |
| `--backup` | `-b` | `false` | Create `.bak` backup before replacing file content |
| `--no-recurse` | | `false` | Do not recurse into subdirectories |
| `--include-hidden`| | `false` | Include hidden files and directories |
| `--gfm` | | `false` | Include GitHub Flavored Markdown table delimiter row (`\| --- \| --- \|`) |
| `--find` | | `false` | Read-only: list each file and each `Suspicious Link Removed` marker found (case-insensitive); modifies nothing |
| `--verbose` | `-v` | `false` | Print detailed scanning diagnostics |
| `--version` | `-V` | | Print the version number and exit |

---

## Example

Given directory structure:
```
water/
└── field/
    ├── north.txt   # Contains mail://eric@ericbell.net and https://polymorph.co
    └── south.txt   # Clean text without links
```

Running:
```bash
./target/release/suspicious-links water/field
```

Results in:
- `north.txt` updated with `[Suspicious Link Removed]` in place of both links.
- `south.txt` remains unchanged.
- `water/field/suspicious-links.md` generated with:
  ```markdown
  | file | link |
  |north.txt | mail://eric@ericbell.net|
  |north.txt | https://polymorph.co|
  ```

---

## Testing

Run all unit and integration tests:

```bash
cargo test
```
