# 🚀 TransactiWar: Team Task List

> [!WARNING]
> This file is for internal development coordination only. **DELETE THIS FILE** before final deployment and submission.

---

## 👥 Collaborative Tasks (To be done together)
- [ ] **Final Security Audit:** Perform a manual peer review of all PHP files for common vulnerabilities (SQLi, XSS, CSRF).
- [ ] **Docker Deployment Test:** Verify everything boots correctly on a clean machine using `docker compose up`.
- [ ] **Integration Testing:** Test the full flow from Registration -> Login -> Transfer -> Receipt.
- [ ] **Phase-1 Report Preparation:** Start drafting the security documentation as per the PDF requirements.

## 🛠️ Individual Tasks

### Member 1
**🔴 Critical / High Issues**
- [ ] **auth.php (HIGH-1):** Fix Login Lockout Bypass - `login_user()` returning string `'locked'` bypasses lockout
- [ ] **config/session.php (HIGH-2):** Fix "Fingerprint Crash" - `resetSession($now)` uses undefined variable `$now`
- [ ] **index.php (H-02):** Fix Diagnostic Leak - Diagnostic Mode leaks database blueprint to public
- [ ] **auth.php:** Fix wrong `session.php` path in `ensure_session_started()`
- [ ] **auth.php:** `get_user_by_public_id()` exposes sensitive data (`email`, `balance_paise`), add separate owner function
- [ ] **auth.php:** `logout_user()` missing `samesite` on cookie deletion, use options array
- [ ] **auth.php:** Uncomment `LOG_LOGIN_LOCKED` logging in `login_user()` to fix lack of security telemetry

**🟡 Medium Issues**
- [ ] **auth.php:** `ensure_session_started()` fails silently; correct path and throw exception on failure
- [ ] **auth.php:** Delete old disconnected/commented code in `require_login()`
- [ ] **auth.php:** `login_user()` bypasses proxy-aware IP detection, use `get_client_ip()`
- [ ] **auth.php:** `require_login()` also bypasses proxy-aware IP detection, use `get_client_ip()`
- [ ] **auth.php:** Replace DB-generated UUID v1 with PHP-generated UUID v4 in `register_user()`
- [ ] **auth.php:** Call `session_regenerate_id(true)` before session destroy in `logout_user()`
- [ ] **auth.php:** Fix `function_exists` check for `logSecurityEvent` instead of `logActivity` in `require_login()`

### General Individual Tasks
- [ ] **Profile hardening:** Ensure `updated_at` timestamps are correctly reflecting changes in all profile edits.
- [ ] **Input Sanitization:** Go through every `$_POST` variable and ensure it's wrapped in our sanitation functions.
- [ ] **CSS/UI Polish:** Make the landing page (now that `index.php` is a redirect) and login forms look professional/premium.
- [ ] **Log Verification:** Confirm that the `activity_logs` table is correctly capturing the `<Webpage, Username, Timestamp, Client's IP Address>` as required.

---





## 📅 Key Deadlines
- **Phase-1 Submission:** March 13th, 2026 @ 11:59 PM
- **Deployment (Phase-1.1):** March 17th, 2026 @ 11:59 PM
- **War Game Starts:** March 18th, 2026 @ 6:00 PM
