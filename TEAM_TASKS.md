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
- [ ] **Profile hardening:** Ensure `updated_at` timestamps are correctly reflecting changes in all profile edits.
- [ ] **Input Sanitization:** Go through every `$_POST` variable and ensure it's wrapped in our sanitation functions.
- [ ] **CSS/UI Polish:** Make the landing page (now that `index.php` is a redirect) and login forms look professional/premium.
- [ ] **Log Verification:** Confirm that the `activity_logs` table is correctly capturing the `<Webpage, Username, Timestamp, Client's IP Address>` as required.

---

## 📅 Key Deadlines
- **Phase-1 Submission:** March 13th, 2026 @ 11:59 PM
- **Deployment (Phase-1.1):** March 17th, 2026 @ 11:59 PM
- **War Game Starts:** March 18th, 2026 @ 6:00 PM
