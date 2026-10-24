# Security

- The backend listens only on 127.0.0.1 and requires a per-launch bearer token. Never expose it publicly or forward the port.
- **Evidence** in the vault is AES-256-GCM encrypted with a key held in the OS credential store; the app refuses to store evidence if it
  cannot get a key (unless you explicitly set `OSINTCC_VAULT_ENCRYPTION=off`).
- The **SQLite database is encrypted** (SQLCipher 4, AES-256) with a subkey of the same master key, and **exported reports are encrypted at
  rest** (`.enc`, decrypted only when you download them). Without the key the app refuses to start rather than open or recreate the
  data. Backups are encrypted with your passphrase. A lost master key (new OS profile, wiped credential store) or backup passphrase
  cannot be recovered: keep an encrypted backup and its passphrase.
- Secrets (API keys) belong in the OS credential store (`POST /api/v1/secrets/{provider}`), never in files, `.env` or reports.
- Releases are **not code-signed**. Verify the SHA-256 from `SHA256SUMS.txt`. Windows SmartScreen will warn.
- Use only on targets and data you are lawfully permitted to examine. Active assessment adapters are absent by default and need a scoped,
  time-limited authorization record plus per-run confirmation. Radio hardware drivers are receive-only.
- Report vulnerabilities privately to the project owner; do not post exploit details or evidence publicly.
- Implemented controls, tests and open gaps: `docs/threat-model.md`. What is stored and where: `docs/privacy.md`.
- Dependency checks (`pip-audit`, `pnpm audit`, `cargo audit`), secret scan and SBOMs: see `docs/progress.md` and `docs/supply-chain/`.
