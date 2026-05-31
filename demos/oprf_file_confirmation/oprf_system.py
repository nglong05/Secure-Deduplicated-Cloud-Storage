from __future__ import annotations

from common import OPRF_LEAK_PATH, VICTIM_REPORT_PATH, build_report, mock_oprf_tag, write_json


SERVER_SECRET = b"demo-only-oprf-server-secret-not-in-db-leak"


def main() -> None:
    report = build_report(
        scan_date="2026-05-29",
        affected=True,
        patched_in_production=False,
    )

    write_json(VICTIM_REPORT_PATH, report)

    leaked_db_row = {
        "source": "oprf-protected files table leak",
        "file_id": "file_8f3a12",
        "created_at": "2026-05-29T02:15:00Z",
        "tag_scheme": "Tag = SHA256(pk_pow), pk_pow derived from OPRF(server_secret, Hash(file))",
        "tag": mock_oprf_tag(report, SERVER_SECRET),
    }
    write_json(OPRF_LEAK_PATH, leaked_db_row)

    print("[oprf] victim report written:", VICTIM_REPORT_PATH)
    print("[oprf] leaked DB row written:", OPRF_LEAK_PATH)
    print("[oprf] leaked tag:", leaked_db_row["tag"])
    print("[oprf] server secret is not present in the leaked DB row")


if __name__ == "__main__":
    main()
