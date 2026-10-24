"""CLI: create or verify a backup without starting the server.  uv run python scripts/backup.py create|verify <file>"""
import sys
from pathlib import Path

from osintcc.backup import create_backup, verify_backup
from osintcc.config import Settings


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "create":
        s = Settings()
        p = create_backup(s)
        print(p)
        res = verify_backup(p)
        print("verified" if res["ok"] else f"VERIFICATION FAILED: {res['problems']}")
        return 0 if res["ok"] else 1
    if len(argv) == 3 and argv[1] == "verify":
        res = verify_backup(Path(argv[2]))
        print(res)
        return 0 if res["ok"] else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
