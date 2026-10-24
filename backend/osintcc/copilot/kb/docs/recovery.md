# Recovery (Windows and Linux paths differ only in the data directory)

Data dir: `%APPDATA%\osintcc` (Windows) or `${XDG_DATA_HOME:-~/.local/share}/osintcc` (Linux); override with `OSINTCC_DATA_DIR`.

## Interrupted work
On start the backend requeues jobs left `running` (event `recovered`), marks open hardware capture sessions and workflow runs
`interrupted` (data already captured is kept), and re-syncs enabled plugins (a tampered one is disabled). Persistence is idempotent
(content-addressed evidence, unique finding keys, slot-idempotent schedules), so a re-run adds no duplicates. Jobs out of attempts
become `interrupted`. Tests: `test_crash_recovery_requeues_running_jobs`, `test_restart_marks_open_sessions_interrupted_without_losing_data`,
`test_interrupted_workflow_run_is_marked_on_startup_and_audited`.

## Backup / verify / restore
1. Create (admin): Settings → *Encryption & backup*, or `POST /api/v1/backups {"passphrase": "…"}` (8+ characters). The container is a SQLite
   online-backup snapshot + vault objects + manifest + SHA-256 list, encrypted with scrypt → AES-256-GCM in 1 MiB authenticated chunks,
   written to a temp file then atomically moved. An unencrypted backup needs `"allow_plaintext": true` and is labelled as such.
2. Verify (read-only): `POST /api/v1/backups/verify {"file": "<name in data/backups>", "passphrase": "…"}`.
3. Preview: `POST /api/v1/backups/restore/preview {"file", "target_name", "passphrase"}` shows collisions.
4. Restore: same body with `"confirm": true`. Restores into `data/restores/<target_name>` (must not exist or be empty). To switch over,
   stop the app and start it with `OSINTCC_DATA_DIR=<that path>`.
The live database is never overwritten. **A lost backup passphrase cannot be recovered.** Vault objects are plaintext *inside* the
encrypted container, so keep the passphrase as carefully as the backup.

## Lost or changed master key
The database, evidence and reports are all protected by one master key stored in the OS credential store (or `OSINTCC_VAULT_KEY`). A new Windows
profile, a wiped credential store, or moving the data directory to another machine without the key makes them unreadable, and **the app refuses to start**
("encrypted with a different key" / "no key is available") instead of creating a new empty database over your data. Recovery path: restore the newest verified backup (it is protected by its own
passphrase and carries a plaintext snapshot inside) into a new directory on the new machine; on first start the app creates a fresh key and re-encrypts
the restored database; run *Encrypt the N older objects* to re-protect old vault files. There is no key escrow.

## Corrupt database
Run `uv run python -m osintcc.doctor --json` and check `GET /api/v1/system/doctor` (`db_integrity`, `audit_chain`). Do not delete the file;
copy it aside, then restore the newest verified backup into a new directory (above).

## Failed migration
`upgrade_to_head` copies the DB to `osintcc.pre-<rev>.bak` before upgrading a non-empty database and runs in one transaction. Downgrade is tested
(`test_downgrade_to_base_then_back`) but is never automatic. Back up before installing a new version.

## Tampered or damaged evidence
Downloads and `/evidence/{id}` re-hash the vault object (for encrypted objects the authentication tag also binds the hash); mismatch → 409
`integrity_failure` and an audit entry. Restore the object from a verified backup.

## The backend will not start
`osintcc-desktop.exe` shows the failure reason. Typical causes are a missing vault key (above), a locked credential store, or a port conflict in
dev mode. See `docs/troubleshooting.md`.
