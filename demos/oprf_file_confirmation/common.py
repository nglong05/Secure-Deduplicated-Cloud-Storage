from __future__ import annotations

import hashlib
import hmac
import json
from datetime import date, timedelta
from pathlib import Path


DEMO_DIR = Path(__file__).resolve().parent
VICTIM_REPORT_PATH = DEMO_DIR / "victim_report.json"
BASELINE_LEAK_PATH = DEMO_DIR / "leaked_db_baseline.json"
OPRF_LEAK_PATH = DEMO_DIR / "leaked_db_oprf.json"

REFERENCE_DATE = date(2026, 5, 29)
SCAN_DATES = [
    (REFERENCE_DATE - timedelta(days=offset)).isoformat() for offset in range(6, -1, -1)
]


def build_report(scan_date: str, affected: bool, patched_in_production: bool) -> dict:
    return {
        "report_type": "daily_vulnerability_gate",
        "company": "FinPay",
        "service": "payment-api",
        "environment": "production",
        "scanner": "trivy",
        "target_cve": "CVE-2026-41721",
        "severity": "CRITICAL",
        "internet_facing": True,
        "fix_available": True,
        "scan_date": scan_date,
        "affected": affected,
        "patched_in_production": patched_in_production,
    }


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def pretty_json(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def baseline_tag(report: dict) -> str:
    return sha256_hex(canonical_json_bytes(report))


def mock_oprf_tag(report: dict, server_secret: bytes) -> str:
    h = hashlib.sha256(canonical_json_bytes(report)).digest()
    oprf_output = hmac.new(server_secret, h, hashlib.sha256).digest()
    pow_seed = hmac.new(oprf_output, b"Ed25519-PoW-Seed", hashlib.sha256).digest()
    mock_pk_pow = hashlib.sha256(b"mock-ed25519-public-key:" + pow_seed).digest()
    return sha256_hex(mock_pk_pow)


def write_json(path: Path, value: dict) -> None:
    path.write_text(pretty_json(value), encoding="utf-8")


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def candidate_reports() -> list[dict]:
    candidates = []
    for scan_date in SCAN_DATES:
        for affected in (False, True):
            for patched in (False, True):
                candidates.append(build_report(scan_date, affected, patched))
    return candidates
