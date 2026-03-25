---
name: efcore-gdpr-obfuscate
description: >
  Generates a GDPR data obfuscation SQL script by scanning EF Core migration files to detect
  tables and columns containing personal data (names, emails, phones, addresses, IDs, passports,
  birth dates, bank details, etc.), then produces an idempotent, deterministic SQL script that
  obfuscates those values in a recognizable and repeatable way.

  Use this skill whenever the user wants to:
  - Generate a GDPR obfuscation/anonymization script for a .NET EF Core project
  - Sanitize a production database for use in dev/test environments
  - Create a repeatable SQL script that masks personal data but leaves system/lookup data untouched
  - Re-scan migrations after schema changes and produce an updated idempotent obfuscation script
  - Anonymize or pseudonymize data for GDPR compliance in any SQL Server database managed by EF Core

  ALWAYS use this skill when the user mentions: GDPR obfuscation, anonymization, data masking,
  sanitizing production data for dev, or generating SQL to replace personal data.

metadata:
  author: Netmedia
  homepage: https://netmedia.agency
  email: netmedia@netmedia.hr
---

# EF Core GDPR Obfuscate Skill

You are helping generate a GDPR-compliant data obfuscation SQL script by analyzing EF Core migration
files. The script must be safe to run against a live (test/dev) database, idempotent, and produce
recognizable output so it's obvious that obfuscation has been applied.

This skill is generic and works with any EF Core project targeting SQL Server.

## Overview of the Process

1. **Scan migrations** — Parse `Up()` methods to build a complete schema map (tables + columns)
2. **Classify columns** — Apply GDPR heuristics to identify personal data columns; skip system tables
3. **Present full review to user** — Show every table/column included AND every table/column skipped, ask for confirmation or changes
4. **Generate SQL** — Produce an idempotent SQL script using deterministic obfuscation functions
5. **Save output** — Write `<projectfolder>-gdpr-obfuscate.sql` to the project root

---

## Step 1: Locate and Scan Migrations

First, find the migrations folder. Common locations:
- `Core/Migrations/`
- `Infrastructure/Migrations/`
- `Data/Migrations/`
- `<ProjectName>/Migrations/`

If the location is unclear, use `Glob: pattern=**/Migrations/*.cs` to find it.

Then build a complete picture of the current schema from the migration files.

**Option A — Python available:** Run `scripts/parse_migrations.py` for a fast, automated scan:
```bash
python scripts/parse_migrations.py <path-to-migrations-folder>
```
The script outputs JSON: `{ "TableName": ["Col1", "Col2", ...] }`.

**Option B — Use your tools directly (preferred in Claude Code):**
Use Glob + Grep to scan the migrations folder efficiently:

1. Find all `CreateTable` calls across migrations:
   ```
   Grep: pattern=CreateTable, path=<migrations-folder>/, output_mode=content
   ```
2. Find all `DropTable` calls to identify removed tables.
3. For tables with GDPR-relevant names, read the specific migration files to get column details.
4. Find any `AddColumn` / `DropColumn` calls that modify those tables.

You do NOT need to read every migration file. Focus on:
- The first large migration (often named `InitialCreate`, `DataFill`, or by date) — contains most of the schema
- Subsequent migrations that add/remove columns on relevant tables

Track:
- Tables created then dropped (exclude from final map)
- Columns added via `AddColumn` after initial `CreateTable`
- Columns removed via `DropColumn`

---

## Step 2: Classify Columns

Apply GDPR heuristics to every column in every table. Identify columns that likely contain
personal data — information that identifies or could identify a natural person.

### Tables to ALWAYS SKIP (system/lookup/reference data)

Skip any table whose name matches these patterns:
- Ends in: `Type`, `Types`, `Status`, `Statuses`, `Category`, `Categories`, `Kind`, `Kinds`
- Named: `Currencies`, `Countries`, `Languages`, `Roles`, `Permissions`, `Claims`, `Settings`,
  `Configurations`, `__EFMigrationsHistory`, `DataProtectionKeys`
- Pure junction/join tables (only FK columns + audit columns, no free-text data)
- ASP.NET Identity role tables: `AspNetRoles`, `AspNetRoleClaims`
  (but NOT `AspNetUsers` — that contains personal data)

### GDPR-Sensitive Column Heuristics

Classify a column as **GDPR-sensitive** if its name (case-insensitive) matches any of:

**Identity & Names:**
- Contains: `FirstName`, `LastName`, `FullName`, `Name` (except `ShortName` on non-person tables)
- Contains: `Username`, `DisplayName`, `NickName`

**Contact:**
- Contains: `Email`, `Phone`, `Mobile`, `ContactNumber`, `Fax`
- Contains: `Address`, `Street`, `PostCode`, `ZipCode`, `Town`, `City`

**Official Identifiers (high sensitivity):**
- Contains: `PersonalIdentificationNumber`, `PassportNumber`, `NationalId`, `TaxId`
- Contains: `ValueAddedTaxNumber`, `VatNumber`, `IdentificationNumber`
- Contains: `DateOfBirth`, `BirthDate`, `BirthPlace`
- Contains: `IbanAndSwift`, `Iban`, `BankAccount`, `BankDetails`

**Domain-specific — detect contextually:**
- Contains: `CustomerName`, `PassengerName`, `TravellerName`, `GuestName`, `PatientName`
- Contains: `FlightDetails`, `ArrivalDetails`, `DepartureDetails`
- Contains: `EmergencyContact`, `EmergencyPhone`
- Contains: `Notes`, `Comment`, `Remarks` — if on a person/contact table (include; skip if on a pure config/lookup table)

**Auth/Security:**
- `PasswordHash` → replace with a fixed non-functional hash string
- `SecurityStamp` → replace with deterministic hex
- Contains: `RefreshToken`, `JwtId`, `Token` (in token/session tables)

### Columns to NEVER obfuscate:
- FK columns (ending in `Id`, `ById`)
- Audit timestamps: `CreatedOnDate`, `ModifiedOnDate`, `DeletedOnDate`, `DisabledOnDate`,
  `CreatedAt`, `UpdatedAt`, `DeletedAt`
- Boolean flags: `IsDeleted`, `IsDisabled`, `IsActive`
- Integer/numeric business data: amounts, counts, rates, quantities
- Lookup FK fields: `CountryId`, `CurrencyId`, `StatusId`, etc.
- Short internal reference codes: `Code`, `Identifier`, `Slug`

---

## Step 3: Present Full Review to User and Wait for Confirmation

**This step is mandatory. Do not generate SQL until the user confirms.**

Present two clear sections using the exact format below.

### Section A — Tables and columns that WILL be obfuscated

One markdown table per included table, listing each column with its obfuscation strategy:

```
## Tables and columns that WILL be obfuscated
(X tables, Y columns total)

### AspNetUsers
| Column | Type | Obfuscation |
|--------|------|-------------|
| FirstName | nvarchar | `obf_FirstName_<hash8>` |
| LastName | nvarchar | `obf_LastName_<hash8>` |
| Email | nvarchar | `obf_<hash8>@obf.invalid` |
| NormalizedEmail | nvarchar | `OBF_<hash8>@OBF.INVALID` |
| PhoneNumber | nvarchar | `+obf-<hash10>` |
| PasswordHash | nvarchar | fixed non-functional hash string |
| SecurityStamp | nvarchar | deterministic hex from hash |

### Customers
| Column | Type | Obfuscation |
|--------|------|-------------|
| FullName | nvarchar | `obf_Name_<hash8>` |
| Email | nvarchar | `obf_<hash8>@obf.invalid` |
| PhoneNumber | nvarchar | `+obf-<hash10>` |
| Address | nvarchar | `obf_Address_<hash8>` |
...
```

### Section B — Tables that WILL be skipped

Every skipped table listed with reason, grouped by category:

```
## Tables that will be SKIPPED
(Z tables total)

**Lookup / reference data (no personal data):**
OrderStatuses, PaymentTypes, ProductCategories, Currencies, Countries, ...

**Junction / relationship tables (FK columns only):**
UserRoles, UserClaims, OrderItems (if FK-only), ...

**Financial / transactional records (linked to people via FK, no personal text):**
Orders, Invoices, Payments, ...

**Operational / structural data (no personal identifiers):**
AuditLogs, ExportHistory, Configurations, ...

**ASP.NET Identity system tables:**
AspNetRoles, AspNetRoleClaims, ...
```

### Confirmation prompt

After both sections, ask:

> **Ready to generate the SQL script?**
> - Type **yes** (or **go**) to proceed with the list above.
> - To **add** a table or column: specify what to include.
> - To **remove** a table or column: specify what to exclude.
> - To **move** a table between lists: just say so.
>
> Output will be saved as: `<projectfolder>-gdpr-obfuscate.sql`

**Wait for the user's response before proceeding.**

If the user requests changes, apply them, confirm the updated lists briefly, then proceed only
once the user approves.

---

## Step 4: Generate the SQL Script

Generate an idempotent SQL script based on the confirmed include list.

### Idempotency Guard

Obfuscated string values are prefixed with `obf_`. The guard skips already-obfuscated rows:

```sql
UPDATE [dbo].[TableName]
SET [ColumnName] = 'obf_' + ...
WHERE [ColumnName] IS NOT NULL
  AND [ColumnName] NOT LIKE 'obf_%';
```

The script can be safely re-run at any time — rows already containing `obf_` are always skipped.

### Deterministic Obfuscation Rules

Seed the hash with the row's primary key (`[Id]`) plus the column name, so:
- The same row always produces the same obfuscated value (deterministic / reproducible)
- Different columns on the same row produce different values

```sql
-- Hash seed pattern:
HASHBYTES('SHA2_256', CAST([Id] AS varchar(50)) + 'ColumnName')
```

| Data Type | Obfuscation Pattern | Example |
|-----------|--------------------|---------|
| First Name | `obf_FirstName_` + hash(8) | `obf_FirstName_A3F2C1B4` |
| Last Name | `obf_LastName_` + hash(8) | `obf_LastName_D9E1F4B2` |
| Full / generic Name | `obf_Name_` + hash(8) | `obf_Name_B7E9D2A1` |
| Email | `obf_` + hash(8) + `@obf.invalid` | `obf_A3F2C1B4@obf.invalid` |
| NormalizedEmail | uppercase of email pattern | `OBF_A3F2C1B4@OBF.INVALID` |
| UserName / NormalizedUserName | `obf_user_` + hash(8) (uppercase for normalized) | `obf_user_A3F2C1B4` |
| Phone / ContactNumber | `+obf-` + hash(10) | `+obf-A3F2C1B4E5` |
| Address / Street | `obf_Address_` + hash(8) | `obf_Address_D4F1A2C3` |
| Town / City | `obf_Town_` + hash(6) | `obf_Town_B3C2D1` |
| PostCode / ZipCode | `OBF-` + hash(4) | `OBF-A1B2` |
| National ID (e.g. OIB, SSN) | `OBF` + N numeric digits from hash | `OBF12345678901` |
| VAT Number | `OBF` + hash(8) | `OBFA3B2C1D4` |
| IBAN / SWIFT | `OBF00 OBFB ` + hash(16) | `OBF00 OBFB A1B2C3D4E5F6G7H8` |
| PasswordHash | Fixed non-functional BCrypt-format string | `$2a$11$OBFUSCATEDpasswordhashOBFUSCATEDpasswordhashOBFUSCA` |
| SecurityStamp | `OBF_` + hash(28) | `OBF_A3F2C1B4...` |
| Token / RefreshToken / JwtId | `obf_token_` + hash(32) | `obf_token_A3F2...` |
| Generic nvarchar / text | `obf_` + ColumnName + `_` + hash(8) | `obf_Notes_A3F2C1B4` |

### Script Structure

```sql
-- ================================================================
-- GDPR Data Obfuscation Script
-- Project:   <ProjectFolder>
-- Generated: <date>
-- Author:    Netmedia (https://netmedia.agency)
--
-- PURPOSE:   Replaces personal data with deterministic, recognizable
--            placeholder values. Safe to run multiple times (idempotent).
--            Obfuscated values are prefixed with 'obf_' for identification.
--
-- INCLUDED:  <comma-separated list of obfuscated tables>
-- SKIPPED:   <comma-separated list of skipped tables>
--
-- USAGE:     Run against TEST or DEV databases ONLY.
--            DO NOT run against the live production database.
-- RE-RUN:    Safe — rows already containing 'obf_' are always skipped.
-- ================================================================

SET NOCOUNT ON;
SET XACT_ABORT ON;
PRINT '>>> Starting GDPR obfuscation...';
PRINT '';

-- ----------------------------------------------------------------
-- Table: AspNetUsers
-- ----------------------------------------------------------------
PRINT '--- Table: AspNetUsers ---';

UPDATE [dbo].[AspNetUsers]
SET [FirstName] = 'obf_FirstName_' + LEFT(CONVERT(varchar(64), HASHBYTES('SHA2_256', CAST([Id] AS varchar(50)) + 'FirstName'), 2), 8)
WHERE [FirstName] IS NOT NULL
  AND [FirstName] NOT LIKE 'obf_%';

-- ... one UPDATE per column per table

PRINT '    AspNetUsers done.';
PRINT '';

PRINT '>>> GDPR obfuscation complete.';
```

---

## Step 5: Determine Output Filename and Save

- Use the current working directory's folder name as the project name
  (e.g., working directory `D:\dev\myapp\api` → project name `api`)
- Save the script as: `<projectfolder>-gdpr-obfuscate.sql` in the project root

After saving, tell the user:
- Full absolute path to the saved file
- Total tables obfuscated and total UPDATE statements generated
- That the script is idempotent — safe to re-run at any time
- How to keep it up to date: re-run this skill after adding new migrations; the skill will rescan
  and regenerate a fresh script — already-obfuscated rows in the database are never double-processed

---

## Re-scan After New Migrations

When the user runs this skill again after schema changes, scan all migrations from scratch.
The regenerated script will include all current GDPR-sensitive columns including newly added ones.
The idempotency guards mean previously-obfuscated rows are always safely skipped when the new
script is applied.
