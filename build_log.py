from __future__ import annotations

import hashlib
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "demo_oprf_data"
LOG_DIR = DATA_DIR / "scanner_logs"
VUL_DB_PATH = DATA_DIR / "vul_service_db.json"
TARGET_CVE = "CVE-2026-41721"
SCAN_DATE = "2026-06-06"
TOTAL_LOGS = 100000


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def pretty_json(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def vulnerable_tag(report: dict) -> str:
    return sha256_hex(canonical_json_bytes(report))


def build_target_report(cve_id: str = TARGET_CVE) -> dict:
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


def build_normal_report(index: int) -> dict:
    services = [
        "auth-service",
        "billing-worker",
        "customer-api",
        "notification-service",
        "admin-panel",
        "risk-engine",
        "settlement-worker",
    ]
    service = services[index % len(services)]
    return {
        "report_type": "trivy_security_scan",
        "schema_version": "1.0",
        "company": "FinPay",
        "service": service,
        "environment": "production",
        "image": f"registry.finpay.internal/{service}:2026.06.{(index % 6) + 1:02d}",
        "scanner": "trivy",
        "scan_run_id": f"scan-normal-{index + 1:04d}",
        "scan_date": f"2026-06-{(index % 6) + 1:02d}",
        "result_type": "no_critical_vulnerability",
        "target_cve": None,
        "package": None,
        "installed_version": None,
        "fixed_version": None,
        "severity": "NONE",
        "internet_facing": service in {"auth-service", "customer-api", "admin-panel"},
        "affected": False,
        "patched_in_production": True,
    }


def reset_output_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for path in LOG_DIR.glob("*.json"):
        path.unlink()


def write_report(path: Path, report: dict) -> None:
    path.write_text(pretty_json(report), encoding="utf-8")


def main() -> None:
    reset_output_dir()

    db_rows = []
    for index in range(TOTAL_LOGS - 1):
        report = build_normal_report(index)
        path = LOG_DIR / f"normal_scan_{index + 1:04d}.json"
        write_report(path, report)
        db_rows.append(
            {
                "file_id": f"vul-file-{index + 1:04d}",
                "object_uri": f"s3://vul-demo/scanner_logs/{path.name}",
                "tag_hex": vulnerable_tag(report),
                "size": path.stat().st_size,
                "created_at": f"2026-06-{(index % 6) + 1:02d}T01:00:00Z",
            }
        )

    target_report = build_target_report()
    target_path = LOG_DIR / "target_payment_api_critical_cve.json"
    write_report(target_path, target_report)
    db_rows.append(
        {
            "file_id": "vul-file-target",
            "object_uri": f"s3://vul-demo/scanner_logs/{target_path.name}",
            "tag_hex": vulnerable_tag(target_report),
            "size": target_path.stat().st_size,
            "created_at": f"{SCAN_DATE}T01:00:00Z",
        }
    )

    leak = {
        "service": "vulnerable-dedup-demo",
        "tag_scheme": "Tag = SHA256(canonical_json_bytes(scanner_report))",
        "total_rows": len(db_rows),
        "rows": db_rows,
    }
    VUL_DB_PATH.write_text(pretty_json(leak), encoding="utf-8")

    print("[build] generated scanner logs:", LOG_DIR)
    print("[build] total logs:", len(db_rows))
    print("[build] normal logs:", TOTAL_LOGS - 1)
    print("[build] critical CVE log:", target_path)
    print("[build] vulnerable DB leak:", VUL_DB_PATH)
    print("[build] target CVE hidden in logs:", TARGET_CVE)


if __name__ == "__main__":
    main()
