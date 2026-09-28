# E-Commerce Platform Security Policy

**Document Reference:** SEC-POL-v2.1
**Effective Date:** September 24, 2026
**Applicability:** All 15 Internal Personnel (Management, Marketing, Ops, Support) & Contractors

---

## 1. Centralized Identity & Access Management (IAM)

- **Single Sign-On (SSO):** All employee authentication must be managed centrally through our primary Identity Provider (Google Workspace / Microsoft 365 Entra ID). Direct, independent account creation on WordPress, Cloudflare, or Hostinger dashboards is strictly prohibited.
- **Multi-Factor Authentication (MFA):** Phishing-resistant MFA (such as dedicated authenticator apps or hardware security keys) is mandatory across all corporate accounts. Legacy SMS-based MFA is prohibited.
- **User Offboarding & Session Limits:** Upon employee departure, HR must notify IT/Security immediately to revoke primary SSO access within 24 hours. Idle sessions on corporate endpoints and web consoles automatically log out after 15 minutes of inactivity.

---

## 2. Least Privilege & Role-Based Access Control (RBAC)

- **Role Assignment:** Customer Support is restricted to WooCommerce "Shop Manager" or "Customer Support" roles. Marketing personnel are restricted to "Editor" or "Contributor" roles. Only designated IT leads hold full "Administrator" rights.
- **Access Reviews:** Account privileges and active user lists must be audited every 60 days by the security lead to eliminate privilege creep and deactivate abandoned accounts.

---

## 3. Workstation & Endpoint Security

- **Device Management:** All laptops used to access company systems must be company-issued, enrolled in corporate MDM, and enforce full-disk encryption, active firewalls, and automatic OS updates.
- **BYOD & Remote Access:** Personal computers, unmanaged mobile devices, or public terminals are strictly prohibited from accessing administrative backends.

---

## 4. Platform Hygiene, Plugin Vetting & Encryption

- **Staging & Plugin Approval:** Personnel are strictly forbidden from installing third-party plugins directly on production. New plugins must undergo security vetting and testing in the Hostinger staging environment before deployment.
- **Patch Management:** WordPress core systems and third-party plugins must run up-to-date versions. Critical security vulnerabilities must be patched within 48 hours of disclosure.
- **Encryption Standards:** Strict TLS 1.2/1.3 network encryption must be enforced globally at the edge to secure data in transit.

---

## 5. Payment Data, Privacy & Retention (PCI-DSS 4.0)

- **Payment Tokenization:** All transactions must route exclusively via WooPayments secure hosted iFrames. Staff members are strictly forbidden from recording, processing, or transmitting raw cardholder data via email, chat, or paper.
- **Data Export & Retention:** Exporting customer database records or PII into local files requires written approval from the business owner. Customer logs and export files must be securely deleted after 90 days unless required by law.

---

## 6. Incident Response & Threat Reporting

- **Incident Escalation:** Any worker who suspects a compromised account, unauthorized system change, or data leak must report it immediately to security@yourcompany.com.
- **Breach Notification Protocol:** Upon confirmation of a breach involving cardholder or personal data, the security lead will activate the Incident Response Plan to isolate affected systems and notify impacted parties within regulatory timelines.
