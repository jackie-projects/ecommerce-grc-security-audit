# E-Commerce Platform Security Policy

**Document Reference:** SEC-POL-v2.2
**Effective Date:** September 27, 2026
**Supersedes:** SEC-POL-v2.1 (September 24, 2026)
**Policy Owner:** Business Owner
**Review Cadence:** Annually, or immediately following any security incident

---

## Change Log (v2.1 → v2.2)

This revision closes the gaps identified in the GRC Compliance Gap Report dated September 25, 2026. Each change below maps to a specific remediation item and control ID for audit traceability.

| Section | Change | Remediation item | Control(s) |
|---|---|---|---|
| 0 (new) | Added role definitions to remove ambiguity between "IT lead," "IT/Security," and "Security Lead" | — | GV.RR-1 |
| 1 | Clarified scope of "primary SSO access" and offboarding revocation | — | PR.AA-4 |
| 3 | Defined "administrative backends" | — | PR.PS-4 |
| 4 | Defined plugin-approval criteria and named approver | 8 | GV.SC-1 |
| 6 | Incorporated the Incident Response Plan by reference and clarified notification scope | 9 | RS.AN-1, RS.MI-1, RS.CO-1 |
| 7 (new) | Added asset & software inventory requirement | 10 | ID.AM-1, ID.AM-2, ID.RA-1 |
| 8 (new) | Added continuous monitoring & alerting requirement | 11 | DE.CM-1, DE.AE-1 |
| 9 (new) | Added recovery validation & post-incident review process | 12 | RC.RP-1, RC.CO-1 |
| 10 (new) | Replaced fixed headcount with role-based applicability; added policy ownership and review cadence | 13 | GV.OC-1 |

---

## 0. Roles & Definitions

To remove ambiguity in how responsibility is assigned throughout this policy:

- **Security Lead** — the individual (or, in a small-team environment, the site owner acting in this capacity) responsible for day-to-day security operations: access reviews, plugin approval, monitoring, and incident response.
- **IT Lead** — the individual responsible for infrastructure administration (hosting, DNS, CDN, backups). May be the same person as the Security Lead in a small organization; where they are the same person, this must be documented rather than assumed.
- **Business Owner** — the individual with final authority over policy approval, data export approval, and breach notification decisions.
- **Administrative backend** — any interface used to configure, manage, or grant access to production systems, including but not limited to: the WordPress `wp-admin` dashboard, the Cloudflare dashboard/API, the Hostinger hPanel, and the WooCommerce admin panel.
- **Primary SSO access** — the employee's Identity Provider (IdP) account and every downstream system that authenticates through it (Google Workspace/Microsoft 365 Entra ID and all connected applications), not merely the IdP login itself.

---

## 1. Centralized Identity & Access Management (IAM)

- **Single Sign-On (SSO):** All employee authentication must be managed centrally through the primary Identity Provider (Google Workspace / Microsoft 365 Entra ID). Direct, independent account creation on WordPress, Cloudflare, or Hostinger dashboards is strictly prohibited.
- **Multi-Factor Authentication (MFA):** Phishing-resistant MFA (dedicated authenticator apps or hardware security keys) is mandatory across all corporate accounts. Legacy SMS-based MFA is prohibited.
- **User Offboarding & Session Limits:** Upon employee departure, HR must notify the Security Lead immediately to revoke **all primary SSO access** — defined per Section 0 to include every connected downstream system, not the IdP login alone — within 24 hours. Idle sessions on corporate endpoints and web consoles automatically log out after 15 minutes of inactivity.
- **Access Verification:** The Security Lead maintains a log of offboarding actions, confirming revocation across all connected systems, retained for one year.

---

## 2. Least Privilege & Role-Based Access Control (RBAC)

- **Role Assignment:** Customer Support is restricted to WooCommerce "Shop Manager" or "Customer Support" roles. Marketing personnel are restricted to "Editor" or "Contributor" roles. Only designated IT Leads hold full "Administrator" rights.
- **Access Reviews:** Account privileges and active user lists must be audited every 60 days by the Security Lead to eliminate privilege creep and deactivate abandoned accounts. Each review is logged in the asset inventory (Section 7) with the reviewer's name and date.

---

## 3. Workstation & Endpoint Security

- **Device Management:** All laptops used to access company systems must be company-issued, enrolled in corporate MDM, and enforce full-disk encryption, active firewalls, and automatic OS updates.
- **BYOD & Remote Access:** Personal computers, unmanaged mobile devices, or public terminals are strictly prohibited from accessing **administrative backends** (defined in Section 0).

---

## 4. Platform Hygiene, Plugin Approval & Encryption

- **Staging Requirement:** Personnel are strictly forbidden from installing third-party plugins directly on production. New plugins must be tested in the Hostinger staging environment before deployment.
- **Plugin Approval Criteria:** A plugin, theme, or third-party integration may be approved for use only if it meets **all** of the following:
  1. Actively maintained, with a security update released within the last 12 months;
  2. Sourced from the official WordPress.org repository, or a vendor with a documented security disclosure process;
  3. No open, unpatched CVEs rated High or Critical at time of review.
- **Named Approver:** The **Security Lead** is the sole approver of new plugins and third-party integrations. Every approved component is logged in the asset inventory (Section 7) with the approval date and reviewer.
- **Ongoing Review:** Approved components are re-evaluated against the criteria above at each 60-day access review (Section 2). Components that no longer qualify are flagged for removal or replacement within 30 days.
- **Patch Management:** WordPress core and all plugins must run up-to-date versions. Critical security vulnerabilities must be patched within 48 hours of disclosure, tracked via the vulnerability monitoring process described in Section 7.
- **Encryption Standards:** TLS 1.2/1.3 encryption must be enforced globally at the edge, with HTTPS force-redirection enabled at all times, to secure data in transit. The Security Lead verifies this setting is active as part of each 60-day access review.

---

## 5. Payment Data, Privacy & Retention (PCI-DSS 4.0)

- **Payment Tokenization:** All transactions must route exclusively via WooPayments secure hosted iFrames. Staff are strictly forbidden from recording, processing, or transmitting raw cardholder data via email, chat, or paper.
- **Data Export & Retention:** Exporting customer database records or PII into local files requires written approval from the Business Owner. Customer logs and export files must be securely deleted after 90 days unless required by law.

---

## 6. Incident Response & Threat Reporting

- **Incident Escalation:** Any worker who suspects a compromised account, unauthorized system change, or data leak must report it immediately to security@example-shop.com. The Security Lead maintains an intake log of all reports, including those later closed as false positives.
- **Incident Response Plan (Reference):** This policy incorporates by reference the organization's Incident Response Plan (IRP), maintained as a controlled document at **incident-response-plan.md**. At minimum, the IRP defines detection and triage steps, containment and eradication procedures, and a communication plan. The IRP is reviewed at least annually or after any incident that triggers its use.
- **Breach Notification Scope:** Upon confirmation of a breach involving cardholder or personal data, the Security Lead activates the IRP to isolate affected systems. **"Impacted parties" requiring notification includes, as applicable:** affected customers, hosting/CDN providers, the payment processor and card networks (if cardholder data is implicated), and relevant regulators, notified within applicable legal timelines.

---

## 7. Asset & Software Inventory

- A current inventory of production systems and software components must be maintained, covering at minimum: hosting accounts, domains, CMS/plugin versions and their approval dates (Section 4), and third-party service integrations (CDN, payment processor, analytics).
- The inventory is reviewed at each 60-day access review (Section 2) and updated immediately upon any change to production infrastructure.
- To operationalize the 48-hour patch SLA (Section 4), the Security Lead subscribes to vendor security advisories or a CVE feed relevant to each inventoried component.

---

## 8. Continuous Monitoring & Alerting

- Production systems must have logging enabled at minimum at the edge (CDN/WAF), application (CMS admin actions), and identity (login attempts) layers. Logs are retained for a minimum of 90 days.
- An alerting mechanism must notify the Security Lead or IT Lead within 24 hours of: repeated failed login attempts, changes to administrator accounts, and any change to a security-relevant configuration (e.g., disabling of HTTPS enforcement or WAF rules).
- Where a dedicated SIEM is not in place, native alerting features of the CDN and hosting provider satisfy this requirement at minimum viable maturity, provided they are actively configured and reviewed — not left at default (off) settings.

---

## 9. Recovery Validation & Post-Incident Review

- Following any incident requiring system restoration, the Security Lead validates recovery through a documented checklist confirming: system integrity, absence of residual unauthorized access, and restoration of normal monitoring and alerting.
- Within 10 business days of recovery, a post-incident review captures root cause and corrective actions, documented and retained for a minimum of one year.
- Where the incident affected customers or payment processing, a summary communication is issued per the notification scope defined in Section 6.

---

## 10. Policy Governance & Applicability

- **Applicability:** This policy applies to all individuals — employees, contractors, or third parties — who have administrative access to production systems, source code, hosting accounts, or customer/payment data, regardless of headcount at any given time.
- **Policy Owner:** The Business Owner (or designee) owns this policy, approves all revisions, and is accountable for its enforcement.
- **Review Cadence:** This policy is reviewed at minimum annually, or immediately following any security incident that reveals a gap in its coverage.
- **Acknowledgement:** Each individual in scope must document acknowledgement of this policy upon onboarding and at each annual review.

---

## Appendix: Open Items

Tracked separately from this policy but referenced for completeness:

- [ ] Attach or link the full Incident Response Plan document (Section 6)
- [ ] Confirm Security Lead / IT Lead role assignment where held by the same individual (Section 0)
- [ ] Complete first full asset & software inventory (Section 7)
- [ ] Configure alerting thresholds with hosting/CDN provider (Section 8)
