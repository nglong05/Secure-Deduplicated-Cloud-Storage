# OPRF File Confirmation Demo

This demo shows why plain deduplication tags are dangerous for files with a
known format and a small secret space.

## Scenario

FinPay runs a nightly vulnerability scanner such as Trivy/Snyk in CI/CD.
The pipeline exports a normalized production vulnerability report and uploads it
to cloud storage.

The attacker has a read-only database leak containing `file_id`, `created_at`,
and `tag`. The attacker does not have the plaintext report, the user's password,
or the OPRF server secret.

Known context:

- service: `payment-api`
- environment: `production`
- scanner: `trivy`
- target CVE: `CVE-2026-41721`
- severity: `CRITICAL`

Unknown fields:

- `scan_date`: one of the last 7 days
- `affected`: `true` or `false`
- `patched_in_production`: `true` or `false`

Search space: `7 * 2 * 2 = 28` candidate files.

## Run

From the project root:

```bash
python demos/oprf_file_confirmation/baseline_system.py
python demos/oprf_file_confirmation/attack_baseline.py

python demos/oprf_file_confirmation/oprf_system.py
python demos/oprf_file_confirmation/attack_oprf.py
```

## Expected result

The baseline version uses:

```text
Tag = SHA256(canonical_report_json)
```

With only the leaked tag, the attacker can brute-force candidate reports offline
and recover:

```text
scan_date = 2026-05-29
affected = true
patched_in_production = false
```

The OPRF-protected version uses a demo-only keyed construction:

```text
h = SHA256(canonical_report_json)
oprf_output = HMAC(server_secret, h)
Tag = SHA256(pk_pow_derived_from(oprf_output))
```

This is not a real OPRF implementation. It only models the important property
needed for the demo: the attacker cannot compute valid candidate tags offline
from a DB leak alone.

## Security message

OPRF does not replace file encryption. It prevents deduplication metadata from
becoming a file-confirmation oracle. In the baseline system, a leaked tag is
enough to confirm whether production is still affected by a critical CVE. In the
OPRF design, the same DB leak is not enough; attacker guesses must go through an
online service where authentication, logging, and rate limiting can be enforced.

## Limitation

This demo proves protection against a passive DB leak and offline brute force.
It does not prove that OPRF alone stops an attacker who has a valid account and
can make unlimited online OPRF queries. For low-entropy reports like this one,
online abuse must be controlled with authentication, quotas, logging, alerting,
and endpoint-specific abuse detection.
