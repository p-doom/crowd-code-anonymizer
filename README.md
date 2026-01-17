<!-- markdownlint-disable first-line-h1 -->
<!-- markdownlint-disable html -->
<!-- markdownlint-disable no-duplicate-header -->

> **Install crowd-code 2.0** to help crowd-source the next-generation coding dataset.
>
> [![Install in Cursor](https://img.shields.io/badge/Install%20in%20Cursor-111111?style=for-the-badge&logo=cursor&logoColor=white)](cursor:extension/p-doom.crowd-code)
> [![Install in VS Code](https://img.shields.io/badge/Install%20in%20VS%20Code-007acc?style=for-the-badge&logo=visualstudiocode&logoColor=white)](vscode:extension/p-doom.crowd-code)
> [![Install in Antigravity](https://img.shields.io/badge/Install%20in%20Antigravity-0f172a?style=for-the-badge&logo=vercel&logoColor=white)](antigravity:extension/p-doom.crowd-code)
<br>
<hr>
<div align="center">
  <img src="https://github.com/p-doom/crowd-code/blob/main/img/pdoom-logo.png?raw=true" width="60%" alt="p(doom)" />
</div>
<hr>
<div align="center" style="line-height: 1;">
  <a href="https://www.pdoom.org/"><img alt="Homepage"
    src="https://img.shields.io/badge/Homepage-p%28doom%29-white?logo=home&logoColor=black"/></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=p-doom.crowd-code"><img alt="VS Code Marketplace"
    src="https://img.shields.io/badge/VS%20Code%20Marketplace-View-2c2c2c?logo=visualstudiocode&logoColor=white"/></a>
  <a href="https://open-vsx.org/extension/p-doom/crowd-code"><img alt="Open VSX Marketplace"
    src="https://img.shields.io/badge/Open%20VSX%20Marketplace-View-262626?logo=eclipseide&logoColor=white"/></a>
  <a href="https://huggingface.co/p-doom"><img alt="Hugging Face"
    src="https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-p--doom-ffc107?color=ffc107&logoColor=white"/></a>
  <br>
  <a href="https://discord.gg/G4JNuPX2VR"><img alt="Discord"
    src="https://img.shields.io/badge/Discord-p%28doom%29-7289da?logo=discord&logoColor=white&color=7289da"/></a>
  <a href="https://github.com/p-doom"><img alt="GitHub"
    src="https://img.shields.io/badge/GitHub-p--doom-24292e?logo=github&logoColor=white"/></a>
  <a href="https://twitter.com/prob_doom"><img alt="Twitter Follow"
    src="https://img.shields.io/badge/Twitter-prob__doom-white?logo=x&logoColor=white"/></a>
  <br>
  <a href="LICENSE.md" style="margin: 2px;">
    <img alt="License" src="https://img.shields.io/badge/License-MIT-f5de53?&color=f5de53" style="display: inline-block; vertical-align: middle;"/>
  </a>
  <br>
</div>

# `crowd-code-anonymizer`

Rust CLI for fast anonymization of CSV datasets that contain crowd-sourced software engineering traces. It scans cells for PII, leaked secrets, developer metadata, and high-entropy tokens, then writes cleaned CSVs and an optional JSON report.

### Features
- Parallel redaction with progress reporting; optional dry-run and interactive review modes.
- PII detector: emails, international phone numbers, IPv4 addresses, SSN/ITIN/PAN/NRIC, IBAN (strict adds extra IDs).
- Secrets detector: AWS keys, GitHub/GitLab tokens, Stripe/OpenAI/HuggingFace/Slack/Discord/Telegram keys, JWTs, generic key/value secrets, and PEM private keys.
- Name detection using the bundled `names-data/{first,last}_names.json` (top-1000 names per country) with accent normalization.
- Custom/structural patterns: user home paths across OSes, SSH key comments, git author lines (strict), plus a high-entropy catch-all to flag unknown tokens.
- JSON report writer capturing file-level stats and each redaction (row/offset/text/label/source).

### Install
- Requires a recent Rust toolchain.
- Build locally: `cargo build --release` (binary at `target/release/anonymize`).
- Or install into your cargo bin: `cargo install --path .`

### Usage
```
anonymize <input> [--output <dir>] [--recursive] [--dry-run] [--strict] [--review] \
  [-j <workers>] [--report <path>] [--names-dir <dir>]
```

### Common flows
- Single CSV → new directory: `anonymize data/events.csv --output anonymized/`
- Directory, recurse, strict detection, and JSON report: `anonymize ./traces --recursive --strict --report report.json`
- Manual review without writing files: `anonymize ./traces --review --dry-run`

### Notes
- Input can be a CSV file or a directory; `--recursive` descends into subdirectories.
- Without `--output`, results are written next to inputs using `file.anonymized.csv`.
- Review mode uses arrow keys (`→` yes, `←` no, `↑` redo) or `y/n`; decisions cache per unique text+label.
- Name detection looks for `first_names.json` and `last_names.json` in `names-data/` by default; override with `--names-dir`.
- The JSON report (via `--report`) includes every redaction with row/line/column offsets to support audits.
- Run tests: `cargo test`
