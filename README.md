# YARA Rules Repository

This repository contains YARA detection rules organized for practical threat detection and long-term maintainability.

Current focus includes campaign-specific rules under `rules/campaigns/`, with room for broader family-based coverage under `rules/families/`.

## Rule Organization

- `rules/campaigns/`: Rules tied to specific campaigns, incidents, or intrusions.
- `rules/families/`: Rules grouped by malware/tool family.
- Platform split (`windows`, `macos`, `linux`, `js`) keeps matching logic contextual and easier to review.

## Usage

### Prerequisites

Install YARA tooling (`yara` and `yarac`) in your environment.

For Ubuntu-based systems:

```bash
sudo apt-get install -y yara
```

### Validate All Rules

From repo root:

```bash
./tests/validate-rules.sh
```

The script compiles each `.yar`/`.yara` file with `yarac` and fails fast on syntax/compile errors.

## Writing and Updating Rules

- Keep metadata complete and consistent (author, dates, family, platform, category, confidence).
- Prefer specific indicators over broad strings to reduce false positives.
- Keep rule names and files descriptive and stable.
- Update `date_modified` and version/revision fields whenever detection logic changes.

See:

- `docs/naming-convention.md`
- `docs/rule-writing-guidelines.md`
- `docs/testing.md`

## Contributing

1. Add or update rules in the appropriate campaign/family folder.
2. Run validation locally with `./tests/validate-rules.sh`.
3. Include context in commit messages (what changed and why).
4. Open a PR with references and expected detection behavior.

## AI Assistance Disclosure

Portions of this repository (including documentation, file scaffolding, and draft rule content) may be created or refined with AI assistance. All security rules and related content should be reviewed and validated by a human maintainer before production use.