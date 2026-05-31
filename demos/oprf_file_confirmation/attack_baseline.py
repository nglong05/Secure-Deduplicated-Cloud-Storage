from __future__ import annotations

from common import BASELINE_LEAK_PATH, baseline_tag, candidate_reports, read_json


def main() -> None:
    leak = read_json(BASELINE_LEAK_PATH)
    leaked_tag = leak["tag"]

    print("[attacker] loaded leaked baseline tag:", leaked_tag)
    print("[attacker] brute-forcing candidate scanner reports offline...")

    for index, candidate in enumerate(candidate_reports(), start=1):
        if baseline_tag(candidate) == leaked_tag:
            print("[FOUND] candidate matched leaked tag")
            print("[FOUND] candidates tried:", index)
            print("[FOUND] scan_date:", candidate["scan_date"])
            print("[FOUND] affected:", candidate["affected"])
            print("[FOUND] patched_in_production:", candidate["patched_in_production"])
            return

    print("[FAILED] no candidate matched")


if __name__ == "__main__":
    main()
