from __future__ import annotations

from common import OPRF_LEAK_PATH, baseline_tag, candidate_reports, read_json


def main() -> None:
    leak = read_json(OPRF_LEAK_PATH)
    leaked_tag = leak["tag"]

    print("[attacker] loaded leaked OPRF-protected tag:", leaked_tag)
    print("[attacker] trying the same offline brute-force strategy...")

    tried = 0
    for candidate in candidate_reports():
        tried += 1
        local_tag_guess = baseline_tag(candidate)
        if local_tag_guess == leaked_tag:
            print("[UNEXPECTED] local SHA256 tag matched an OPRF-protected tag")
            print(candidate)
            return

    print("[BLOCKED] no local candidate tag matched")
    print("[BLOCKED] candidates tried:", tried)
    print("[BLOCKED] DB leak alone cannot confirm affected/patched status offline")
    print("[BLOCKED] online OPRF queries are outside this passive DB-leak threat model")
    print("[BLOCKED] if online queries are allowed, enforce auth, quotas, logging, and abuse alerts")


if __name__ == "__main__":
    main()
