# Profile Test Plan

## Field Validation
- First/Last name: reject empty strings.
- Phone: accept E.164 (`+12025550123`), reject malformed.
- Bio: strip HTML tags, limit length.
 

## Migration Verification
- After `001_profile_core_up.sql`, columns exist and indexes present.
- Backfill splits `name` into `first_name`/`last_name`.
- CHECK constraints active (verify with invalid inserts).

## Performance Benchmarks
- Name search via `(first_name, last_name)` index under 10k users.
 

## Security Tests
- Foreign key cascade: deleting a `users.id` removes related `calculation_history`.