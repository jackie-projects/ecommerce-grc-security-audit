# Incident Response Plan (IRP)

**Document Reference:** IRP-v1.0
**Referenced by:** SEC-POL-v2.2, Section 6
**Owner:** Security Lead
**Review Cadence:** Annually, or immediately after any incident that triggers this plan

---

## Purpose

This plan defines the steps to detect, contain, and recover from a security incident affecting example-shop.com or its supporting infrastructure (Cloudflare, Hostinger, WordPress, WooCommerce), and who must be notified and when.

---

## Roles & Contacts

| Role | Name | Contact |
|---|---|---|
| Security Lead (incident commander) | (Site Owner) | security@example-shop.comm |
| IT Lead (infrastructure access) | (Site Owner) | security@example-shop.com |
| Business Owner (external comms / legal decisions) | (Site Owner) | security@example-shop.com |
| Hosting provider support | Hostinger | https://www.hostinger.com/support/ |
| CDN/edge provider support | Cloudflare | https://www.support.cloudflare.com/s/ |
| Payment processor support | [WooPayment] |https://woocommerce.com/my-account/contact-support |

Report suspected incidents to: **security@example-shop.com.com*

---

## Severity Levels

| Level | Definition | Example |
|---|---|---|
| **Low** | No evidence of unauthorized access or data exposure | Suspicious login attempt, blocked |
| **Medium** | Contained unauthorized access, no confirmed data exposure | Compromised low-privilege account, caught quickly |
| **High** | Confirmed unauthorized access or configuration change | Admin account compromised, WAF/HTTPS disabled without approval |
| **Critical** | Confirmed data exposure, especially payment/customer data | Database export detected, cardholder data implicated |

---

## Phase 1 — Detection & Triage (Target: within 1 hour of report)

1. Whoever receives the report (via security@yourcompany.com or direct observation) notifies the **Security Lead** immediately.
2. Security Lead confirms the report is credible and assigns a severity level (above).
3. Security Lead opens an incident log (timestamp, description, severity, actions taken from this point forward).

---

## Phase 2 — Containment (Target: within 4 hours for High/Critical)

Depending on what's affected:

- **Compromised account:** Force password reset and revoke active sessions via the Identity Provider immediately. Disable the account if departure/compromise is confirmed.
- **Malicious plugin/code on WordPress:** Put the site in maintenance mode; disable the affected plugin/theme via `wp-admin` or SFTP if admin access is untrusted.
- **Edge/Cloudflare misconfiguration:** Revert the change (e.g., re-enable "Always Use HTTPS," restore Security Level) directly in the Cloudflare dashboard.
- **Suspected payment data exposure:** Immediately notify the payment processor and Business Owner; do not attempt to independently investigate cardholder data — that is the processor's responsibility under PCI DSS.

---

## Phase 3 — Eradication

1. Identify root cause (e.g., leaked credential, unpatched plugin, misconfigured setting).
2. Remove the malicious artifact or close the exploited gap.
3. Rotate any credentials or API tokens that may have been exposed.
4. Confirm no backdoors or unauthorized admin accounts remain (cross-check against the asset inventory, SEC-POL-v2.2 Section 7).

---

## Phase 4 — Recovery & Validation

Per SEC-POL-v2.2, Section 9:

1. Restore affected systems from a known-clean backup or configuration state.
2. Validate: system integrity, no residual unauthorized access, monitoring/alerting restored to normal.
3. Document validation steps and sign-off in the incident log.

---

## Phase 5 — Notification

Per SEC-POL-v2.2, Section 6. For **Medium severity and above**, notify as applicable:

- [ ] Affected customers
- [ ] Hosting provider (Hostinger) and CDN provider (Cloudflare)
- [ ] Payment processor / card networks — **required if cardholder data is implicated**
- [ ] Relevant regulators — **required if personal data of residents in a regulated jurisdiction is implicated**, within the timeline required by applicable law

Business Owner approves all external communications before they are sent.

---

## Phase 6 — Post-Incident Review (within 10 business days of recovery)

1. Security Lead documents: root cause, timeline, what worked, what didn't.
2. Identify and assign corrective actions (e.g., policy update, new monitoring rule, plugin removal).
3. Update the asset inventory, policy, or monitoring configuration as needed.
4. Retain the review record for a minimum of one year.

---

## Quick Reference

| If you suspect... | Do this first |
|---|---|
| A compromised admin account | Force logout + password reset via Identity Provider |
| A malicious or vulnerable plugin | Put site in maintenance mode, disable the plugin |
| HTTPS/WAF disabled unexpectedly | Re-enable in Cloudflare dashboard, then investigate why it changed |
| Unauthorized data export | Notify Business Owner and Security Lead immediately; do not delete evidence |
| Anything involving payment data | Notify payment processor immediately; do not investigate cardholder data yourself |
