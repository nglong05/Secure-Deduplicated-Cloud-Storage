from __future__ import annotations

from common import BASELINE_LEAK_PATH, VICTIM_REPORT_PATH, baseline_tag, build_report, write_json


def main() -> None:
    report = build_report(
        scan_date="2026-05-29",
        affected=True,
        patched_in_production=False,
    )

    write_json(VICTIM_REPORT_PATH, report)

    leaked_db_row = {
        "source": "baseline files table leak",
        "file_id": "file_8f3a12",
        "created_at": "2026-05-29T02:15:00Z",
        "tag_scheme": "Tag = SHA256(canonical_report_json)",
        "tag": baseline_tag(report),
    }
    write_json(BASELINE_LEAK_PATH, leaked_db_row)

    print("[baseline] victim report written:", VICTIM_REPORT_PATH)
    print("[baseline] leaked DB row written:", BASELINE_LEAK_PATH)
    print("[baseline] leaked tag:", leaked_db_row["tag"])


if __name__ == "__main__":
    main()
