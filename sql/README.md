# SQL Operations Guide

This guide covers common SQL operations for SoilCalcify, including backups and schema changes.

## What to Back Up

- Table: `calculation_history`
- Related table: `users` (for `user_id` foreign key references)
- Optionally, back up the entire database for consistency.

## Recommended Schedule

- Daily full backup of `calculation_history` and `users`.
- Hourly incremental backups if binary logs are enabled.
- Retention: keep daily backups for 30 days; weekly backups for 6 months.

## Backup Commands (MySQL)

Run these from PowerShell on Windows (adjust MySQL bin path and credentials):

```powershell
# Full database backup
& "C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqldump.exe" `
  -u <USER> -p<PASSWORD> --single-transaction --routines --events `
  <DATABASE_NAME> > "C:\\backups\\soilcalcify-<DATABASE_NAME>-full-$(Get-Date -Format yyyyMMdd).sql"

# Specific tables backup
& "C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysqldump.exe" `
  -u <USER> -p<PASSWORD> --single-transaction `
  <DATABASE_NAME> calculation_history users > "C:\\backups\\soilcalcify-history-$(Get-Date -Format yyyyMMdd).sql"
```

If using Laragon, you can also run `mysqldump` from Laragon's MySQL bin directory.

## Verify Backups

- Inspect the backup file sizes and ensure they’re non-empty.
- Optionally, run `mysql` to load into a staging DB and check:

```sql
SHOW TABLES;
SELECT COUNT(*) FROM calculation_history;
SHOW INDEX FROM calculation_history;
```

## Restore Procedure

```powershell
& "C:\\Program Files\\MySQL\\MySQL Server 8.0\\bin\\mysql.exe" `
  -u <USER> -p<PASSWORD> <DATABASE_NAME> < "C:\\backups\\soilcalcify-history-YYYYMMDD.sql"
```

After restore, verify foreign keys and indexes:

```sql
SELECT COUNT(*) FROM calculation_history;
SHOW INDEX FROM calculation_history;
```

## Performance Notes

- Indexes: `INDEX(user_id, performed_at)`, `INDEX(performed_at)`, optional `FULLTEXT(params, result)`.
- For large imports or restores, consider temporarily disabling foreign key checks and re-enabling afterward:

```sql
SET FOREIGN_KEY_CHECKS=0;
-- import data
SET FOREIGN_KEY_CHECKS=1;
```

## Offsite Storage

- Sync backup files to offsite storage (e.g., S3, Azure Blob) using `rclone` or native client tools.
- Encrypt backups at rest and in transit.

## Automation

 - Use Windows Task Scheduler to run the PowerShell backup script daily.
 - Log success/failure and alert on failures.

## Remove Avatar Columns (if previously added)

If your `users` table contains avatar-related columns from earlier versions, you can drop them with:

```sql
SOURCE drop_avatar_columns.sql;
```

This removes `avatar_path`, `avatar_prev_path`, `avatar_mime`, `avatar_size`, and encrypted BLOB fields (`avatar_blob`, `avatar_iv`, `avatar_tag`).