# efcore-gdpr-obfuscate

A Claude Code skill that scans EF Core migration files to detect GDPR-sensitive columns and
generates an idempotent, deterministic SQL Server obfuscation script — ready to apply against
any dev or test database.

## What It Does

- Parses all EF Core migrations (`CreateTable`, `AddColumn`, `DropColumn`, `RenameColumn`) to
  build an accurate, up-to-date schema map
- Classifies columns as GDPR-sensitive (names, emails, phones, addresses, national IDs, IBAN,
  passport numbers, birth dates, auth tokens, etc.)
- Skips system/lookup/reference tables automatically
- Presents a full review of **which tables and columns will be obfuscated** and **which will be
  skipped** — with the obfuscation strategy shown for every column — before generating anything
- Accepts additions, removals, or moves between lists before proceeding
- Generates a `.sql` script named `<projectfolder>-gdpr-obfuscate.sql`

## Key Properties of the Generated Script

| Property | Description |
|----------|-------------|
| **Idempotent** | Safe to re-run — rows already prefixed with `obf_` are always skipped |
| **Deterministic** | Same row always produces the same obfuscated value (seeded by primary key + column name) |
| **Recognizable** | Obfuscated values are clearly marked: `obf_Name_A3F2C1B4`, `obf_user@obf.invalid`, `OBF12345678901` |
| **Re-scannable** | Re-run the skill after adding new migrations to pick up newly added GDPR columns |

## Requirements

- .NET EF Core project with a standard migrations folder
- SQL Server database

## Usage

Just describe what you want:

```
"Generate a GDPR obfuscation script for this project"
"Anonymize the database for dev"
"Sanitize production data for testing"
"Re-scan migrations and regenerate the obfuscation script"
```

## Author

**Netmedia**
Website: https://netmedia.agency
Email: netmedia@netmedia.hr
