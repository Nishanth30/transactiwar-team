# Transactiwar Security Assessment (OWASP 2025 Mapping)

- Date: 2026-03-05 (IST)
- Repository: `/Users/apollo/Desktop/GitHub/transactiwar-team`
- Assessor mode: static audit + safe runtime validation + isolated aggressive fuzzing
- Runtime target: isolated Docker Compose project `txwsec` on `http://127.0.0.1:18080`
- Raw artifacts: `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/`

## Scope

Code scope reviewed:
- `public/`
- `includes/`
- `config/`
- `database/`
- `docker/`
- `.github/workflows/`

Runtime scope:
- `docker/docker-compose.yml` stack in isolated project `txwsec`.

## Tooling Installed and Used

Installed with Homebrew and version-verified:
- `trivy` 0.69.3
- `grype` 0.109.0
- `syft` 1.42.1

Version evidence:
- `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/tool_versions.txt`

Primary scan artifacts:
- `trivy_fs.json`
- `trivy_config.json`
- `sbom_cyclonedx.json`
- `grype_sbom_vulns.json`
- `trivy_app_image.json`
- `trivy_mysql_image.json`
- `docker_scout_app.md`
- `docker_scout_mysql.md`

Runtime evidence:
- `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/runtime/`

## Executive Summary

Confirmed findings by severity:
- High: 4
- Medium: 5
- Low: 3

Top risks:
1. Session fingerprint mismatch path crashes with fatal error and exposes stack traces/paths.
2. Database diagnostic endpoint exists at `/index.php` with no authentication gate when diagnostic mode is enabled.
3. Runtime component risk includes critical/high vulnerabilities in `mysql:8.4` image.
4. CSRF/session weaknesses: logout via GET (no anti-forgery) and CSRF token leakage into URL logs.

What tested clean in this assessment:
- SQL injection attempts on login/search paths did not bypass authentication.
- Tested reflected/stored XSS payloads were escaped in observed output paths.
- File-upload PHP payload was rejected by MIME validation.
- Transfer race test did not create double-spend in tested scenario (transaction locking held).
- No active SSRF sinks or unsafe deserialization calls were identified in code sweep.

## Prioritized Findings

### H-01: Session reset crash and stack-trace disclosure (exception handling failure)

- Severity: High
- OWASP 2025 mapping: A10 Mishandling of Exceptional Conditions, A05 Security Misconfiguration
- Exploitability: High (low complexity once session fingerprint mismatch is induced)
- Confidence: High

#### Evidence

Static:
- `config/session.php` calls `resetSession($now)` before `$now = time()` is initialized.
  - `config/session.php:64`
  - `$now` initialized later at `config/session.php:73`
- Login route forces error display:
  - `public/login.php:4` (`ini_set('display_errors', 1)`)
  - `public/login.php:5` (`error_reporting(E_ALL)`)

Dynamic:
- Runtime proof contains full warning/fatal stack trace with internal filesystem paths:
  - `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/runtime/exception_second.txt`
- `runtime_summary.txt` confirms:
  - `exception_fatal_visible=YES`

#### Impact

- A fingerprint mismatch can terminate request handling with fatal error.
- Internal path disclosure and code structure leak to end users.
- Session robustness degrades (DoS against affected session flow).

#### Recommended fix

- Move `$now = time()` above any call to `resetSession($now)`.
- Remove `display_errors=1` from public routes; keep detailed errors in server logs only.
- Add a regression test for fingerprint mismatch to ensure graceful session reset (no fatal).

#### Verification

- Re-run mismatch scenario and assert no warning/fatal HTML in response.
- Confirm response is a clean redirect/login reset and errors only in logs.

---

### H-02: Unauthenticated diagnostic endpoint behavior in `/index.php`

- Severity: High
- OWASP 2025 mapping: A05 Security Misconfiguration, A01 Broken Access Control
- Exploitability: Medium (depends on env toggle)
- Confidence: High

#### Evidence

Static:
- Route is unauthenticated and always reachable:
  - `public/index.php` has no `require_login()` call.
- Diagnostic gate is environment-variable based only:
  - `public/index.php:27` checks `APP_DIAGNOSTIC_MODE`
  - If enabled, route queries and lists DB tables (`public/index.php:40-46`).

Dynamic:
- Current runtime response confirms endpoint is public and mode-driven:
  - `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/runtime/index_response.txt`
  - Output includes `PHP running` and `Diagnostic mode disabled.`

#### Impact

- If `APP_DIAGNOSTIC_MODE=1` is set in any non-dev environment, an unauthenticated user can enumerate schema table names.
- Increases attack-surface reconnaissance quality.

#### Recommended fix

- Remove diagnostic behavior from public route.
- If diagnostic behavior is retained, gate behind strict admin authentication/authorization and environment allowlist.
- Return generic page content for unauthenticated users regardless of environment flag.

#### Verification

- Set `APP_DIAGNOSTIC_MODE=1` in a test stack and confirm unauthenticated users still cannot access diagnostic data.

---

### H-03: Runtime image vulnerabilities include critical/high CVEs (supply-chain)

- Severity: High
- OWASP 2025 mapping: A06 Vulnerable and Outdated Components
- Exploitability: Medium (depends on reachable vulnerable code paths)
- Confidence: High

#### Evidence

- `trivy_mysql_image.json`: 1 critical, 6 high, 12 medium, 1 low.
- Representative IDs found:
  - `CVE-2025-68121` (critical, Go stdlib in mysql image tooling layer)
  - `CVE-2026-26007` (high, `cryptography`)
- Docker Scout corroboration:
  - `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/docker_scout_mysql.md`

#### Impact

- Known CVEs in deployed images increase compromise probability over time and complicate compliance posture.

#### Recommended fix

- Pin and regularly rebuild to patched digests.
- Use scanner-gated CI policy (block merge for critical/high above threshold).
- Track exploitability context for each CVE and document approved exceptions.

#### Verification

- Re-scan updated image digests and confirm critical/high count reduction.

---

### H-04: CSRF token leakage into GET URLs and server logs

- Severity: High
- OWASP 2025 mapping: A02 Cryptographic Failures (token handling), A09 Security Logging and Monitoring Failures
- Exploitability: Medium (requires access to logs/history/referrer channels)
- Confidence: High

#### Evidence

Static:
- Search form uses `GET` and includes CSRF hidden field:
  - `public/searchbox.php:34-36`
- CSRF validator intentionally skips GET methods:
  - `includes/csrf.php:301-305`

Dynamic:
- Apache access logs captured full CSRF token in query string:
  - `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/runtime/csrf_token_query_logs.txt`
  - Example logged request includes `?csrf_token=<hmac.raw>&q=probe2`

#### Impact

- CSRF token exposure in logs/history creates avoidable token disclosure channel.
- Weakens anti-forgery assurances where log access exists.

#### Recommended fix

- Remove CSRF field from all GET/read-only forms.
- Keep CSRF tokens only in POST body or custom header.
- Add log scrubbing for sensitive query params.

#### Verification

- Re-run search requests and confirm access logs contain no CSRF token value in URL.

---

### M-01: Logout CSRF (state-changing action on GET)

- Severity: Medium
- OWASP 2025 mapping: A01 Broken Access Control, A07 Identification and Authentication Failures
- Exploitability: High
- Confidence: High

#### Evidence

Static:
- Logout endpoint is GET-only and unprotected:
  - `public/logout.php:4-10`
- UI exposes logout as plain link:
  - `public/index.php:10`

Dynamic:
- Runtime evidence confirms GET request logs out active session:
  - `runtime/logout_before.txt`
  - `runtime/logout_get.txt`
  - `runtime/logout_after.txt`
  - `runtime_summary.txt` contains `logout_get_kills_session=YES`

#### Impact

- Any cross-site request (e.g., image tag/link) can force logout.

#### Recommended fix

- Convert logout to POST-only endpoint.
- Require CSRF validation on logout POST.
- Update templates to submit logout via hidden form.

#### Verification

- Confirm GET `/logout.php` no longer destroys session.
- Confirm POST without valid CSRF is rejected.

---

### M-02: Login lockout logic flaws (ambiguous return handling + dual counter updates)

- Severity: Medium
- OWASP 2025 mapping: A04 Insecure Design, A07 Identification and Authentication Failures
- Exploitability: Medium
- Confidence: High

#### Evidence

Static:
- `login_user()` returns mixed types: `bool|string` (`true`, `false`, `'locked'`):
  - `includes/auth.php:207`, `includes/auth.php:221`
- Login handler treats any truthy value as success:
  - `public/login.php:48-55`
- Failed login attempts are incremented in two separate places for one request:
  - `includes/auth.php:263` (`record_failed_attempt`)
  - `public/login.php:57` (`recordFailedLogin`)

Dynamic:
- Runtime sequence shows attempts increasing by 2 per invalid attempt:
  - `runtime/lockout_sequence.tsv`
  - attempts observed: 2, 4, 6

#### Impact

- Lockout behavior becomes inconsistent/unpredictable.
- Can create unintended early lockouts (DoS against users/IPs).
- Mixed-type return handling is a latent auth bug source.

#### Recommended fix

- Replace mixed return type with explicit enum/status constants.
- Use one lockout implementation only (single source of truth).
- In login handler, compare explicit status values instead of truthiness.

#### Verification

- Re-run lockout tests and confirm deterministic threshold behavior and no double increments.

---

### M-03: Security headers are not enforced uniformly across entrypoints

- Severity: Medium
- OWASP 2025 mapping: A05 Security Misconfiguration
- Exploitability: Medium
- Confidence: High

#### Evidence

Static:
- `send_security_headers()` exists but is not called in several public entrypoints (examples):
  - `public/register.php` (none)
  - `public/profile.php` (none)
  - `public/searchbox.php` (none)
  - `public/view_profile.php` (none)
  - `public/index.php` (none)
- Header framework defined in:
  - `includes/header.php:212-309`

Dynamic:
- Route matrix shows HSTS/COEP/CSP-nonce missing on multiple routes:
  - `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/runtime/header_matrix.tsv`

#### Impact

- Inconsistent browser-side protections across application pages.
- Easier exploitation pivot if weaker route is targeted.

#### Recommended fix

- Centralize bootstrap so all `public/*.php` pass through one mandatory header/session/auth prelude.
- Add automated header conformance test for all routes.

#### Verification

- Re-run header matrix and confirm mandatory headers are present on all intended routes.

---

### M-04: CI/CD and image pinning gaps (integrity risk)

- Severity: Medium
- OWASP 2025 mapping: A08 Software and Data Integrity Failures
- Exploitability: Medium
- Confidence: High

#### Evidence

GitHub Actions:
- Uses mutable references instead of commit SHA pinning:
  - `.github/workflows/security.yml:14` (`actions/checkout@v4`)
  - `.github/workflows/security.yml:19` (`anthropics/claude-code-security-review@main`)
  - `.github/workflows/semgrep.yml:25` (`actions/checkout@v4`)

Container image tags are mutable:
- `docker/Dockerfile:1` (`php:8.2-apache`)
- `docker/docker-compose.yml:3` and `:30` (`mysql:8.4`)

#### Impact

- Upstream supply-chain changes can alter build/runtime behavior without repository diffs.

#### Recommended fix

- Pin workflow actions to full commit SHA.
- Pin base images by digest and rotate via controlled update process.

#### Verification

- CI policy check fails on non-SHA action refs and non-digest image refs.

---

### M-05: Exception message reflection in transfer failure path

- Severity: Medium
- OWASP 2025 mapping: A10 Mishandling of Exceptional Conditions
- Exploitability: Medium
- Confidence: Medium

#### Evidence

- Transfer catch block stores raw exception text in session:
  - `includes/process_payment.php:97`
- Failure page renders session error to user:
  - `public/failure.php:14-16`

#### Impact

- In failure edge-cases (especially DB/driver exceptions), internal messages may leak to user.

#### Recommended fix

- Map internal exceptions to generic user-safe messages.
- Keep detailed exception context in server logs only.

#### Verification

- Trigger DB exception in test and confirm no internal stack/SQL details are displayed to user.

---

### L-01: Container hardening baseline gaps

- Severity: Low
- OWASP 2025 mapping: A05 Security Misconfiguration
- Exploitability: Medium
- Confidence: High

#### Evidence

Trivy misconfig findings on `docker/Dockerfile`:
- `DS-0002`: container runs as root (no `USER` instruction).
- `DS-0026`: no `HEALTHCHECK`.

Artifact:
- `/Users/apollo/Desktop/GitHub/transactiwar-team/reports/pentest/2026-03-05/trivy_config.json`

#### Recommended fix

- Add dedicated non-root runtime user.
- Add container `HEALTHCHECK` and wire into orchestrator policy.

---

### L-02: CSRF origin checking disabled by default

- Severity: Low
- OWASP 2025 mapping: A05 Security Misconfiguration
- Exploitability: Low
- Confidence: High

#### Evidence

- `includes/csrf.php:18` sets `CSRF_ALLOWED_ORIGIN` to empty string.
- `_csrfCheckOrigin()` bypasses origin validation when value is empty (`includes/csrf.php:90-96`).

#### Impact

- Reduces defense-in-depth against token exfiltration/replay scenarios.

#### Recommended fix

- Set explicit allowed origin in environment and enforce it in production.

---

### L-03: `secure` cookie decision trusts `X-Forwarded-Proto` directly

- Severity: Low
- OWASP 2025 mapping: A05 Security Misconfiguration
- Exploitability: Low/Medium (depends on proxy trust boundary)
- Confidence: Medium

#### Evidence

- `config/session.php:29-33` sets `$secure` true if `HTTP_X_FORWARDED_PROTO === 'https'`.

#### Impact

- In misconfigured proxy chains, client-controlled headers can affect cookie security mode.

#### Recommended fix

- Only trust forwarded proto from known reverse proxy layer (web server enforcement), not direct client header.

## Dynamic Validation Summary (Safe + Aggressive)

Confirmed runtime checks:
- Lockout behavior captured (`lockout_sequence.tsv`).
- Logout CSRF behavior captured (`logout_*`).
- Header coverage matrix captured (`header_matrix.tsv`).
- Fatal exception leakage captured (`exception_second.txt`).
- SQLi payload attempts did not bypass login (`sqli_login_matrix.tsv`).
- Search payload probes returned escaped output (`search_payload_matrix.tsv`).
- Stored XSS probe marker persisted as text, script tag not executed in tested output (`stored_xss_check.txt`).
- Upload bypass test rejected PHP payload (`upload_bypass_attempt.txt`, `runtime_summary.txt`).
- Transfer race test produced one success only in tested run (`race_transfer_check.txt`).
- Aggressive fuzz pass returned no observed 5xx (`fuzz_status_histogram.txt`, `runtime_summary.txt`).

## OWASP Top 10:2025 Coverage Matrix

| Category | Status | Notes |
|---|---|---|
| A01 Broken Access Control | Confirmed finding | Logout CSRF (state change on GET); no IDOR balance leak found in tested profile path. |
| A02 Cryptographic Failures | Confirmed finding | CSRF token handling weakness (token in URL/logs). Password hashing usage appears modern (`password_hash`). |
| A03 Injection | Reviewed/no issue found | SQLi/XSS payload probes in tested paths did not yield exploitation. |
| A04 Insecure Design | Confirmed finding | Lockout design inconsistency (mixed return contract + dual counters). |
| A05 Security Misconfiguration | Confirmed finding | Header inconsistency, diagnostic mode exposure risk, CSRF origin unset, container hardening gaps. |
| A06 Vulnerable and Outdated Components | Confirmed finding | Critical/high CVEs in runtime images (notably mysql image stack). |
| A07 Identification and Authentication Failures | Confirmed finding | Lockout/auth flow logic weaknesses; logout semantics. |
| A08 Software and Data Integrity Failures | Confirmed finding | Unpinned workflow actions and mutable image tags. |
| A09 Security Logging and Monitoring Failures | Confirmed finding | Sensitive CSRF token appears in URL logs due GET token placement. |
| A10 Mishandling of Exceptional Conditions | Confirmed finding | Session mismatch fatal and error disclosure path. |

## User-Requested Category Coverage Matrix

| Requested Category | Status | Notes |
|---|---|---|
| AuthN/AuthZ | Confirmed finding | Lockout logic flaw, logout CSRF. |
| Injection vectors | Reviewed/no issue found | SQLi/XSS probes resisted in tested endpoints. |
| Privilege escalation | Reviewed/no issue found | No direct privilege escalation path demonstrated. |
| Unsafe data handling | Confirmed finding | CSRF token leaked in URL logs; transfer exception reflection. |
| Cryptographic weaknesses | Confirmed finding | Token handling weakness (exposure), origin enforcement disabled by default. |
| Dependency vulnerabilities | Confirmed finding | Trivy/Scout image CVEs (critical/high present). |
| Exposed credentials/secrets | Reviewed/no issue found | No committed plaintext secrets detected in scope scan. |
| Improper input validation | Confirmed finding | Lockout control-flow contracts are ambiguous; otherwise many inputs validated/sanitized. |
| Session management flaws | Confirmed finding | Fatal reset path on fingerprint mismatch; secure-cookie trust boundary caveat. |
| Insecure APIs/routes | Confirmed finding | Public diagnostic behavior via `/index.php` when mode enabled. |
| File handling vulnerabilities | Reviewed/no issue found | Tested PHP upload bypass blocked; file naming/MIME checks present. |
| Deserialization risks | Reviewed/no issue found | No unsafe unserialize sink identified in scope. |
| Broken access controls | Confirmed finding | Logout CSRF and unauth diagnostic behavior risk. |
| SSRF | Reviewed/no issue found | No actionable SSRF sink identified in sweep. |
| Systemic/security design weaknesses | Confirmed finding | Inconsistent security-header enforcement and mixed auth lockout paths. |

## Key Remediation Order

1. Fix session fatal/error disclosure path (`config/session.php` + `public/login.php`).
2. Remove/lock down diagnostic behavior on `/index.php`.
3. Convert logout to POST + CSRF and remove CSRF token from GET forms.
4. Refactor login lockout into a single explicit state machine.
5. Centralize security header bootstrap across all public routes.
6. Address image/workflow supply-chain hardening (pinning + CVE reduction plan).

## Reproduction Notes (Selected)

- Lockout sequencing evidence: `runtime/lockout_sequence.tsv`
- Logout CSRF behavior: `runtime/logout_before.txt`, `runtime/logout_get.txt`, `runtime/logout_after.txt`
- Session fatal: `runtime/exception_second.txt`
- Header inconsistency: `runtime/header_matrix.tsv`
- CSRF token log leakage: `runtime/csrf_token_query_logs.txt`
- SQLi probes: `runtime/sqli_login_matrix.tsv`
- XSS probes: `runtime/search_payload_matrix.tsv`, `runtime/stored_xss_check.txt`
- File upload bypass attempt: `runtime/upload_bypass_attempt.txt`
- Race transfer behavior: `runtime/race_transfer_check.txt`
- Fuzz outcomes: `runtime/fuzz_status_histogram.txt`

## Limitations and Residual Risk

- Scanner findings include transitive/tooling-layer packages that may have limited exploitability in this app context; prioritize patching by reachable attack surface.
- Dynamic tests were non-destructive and limited to local isolated environment behavior.
- Absence of finding in tested paths is not proof of absence in untested flows.

