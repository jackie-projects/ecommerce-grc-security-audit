# GRC Compliance Gap Report

**Organization:** Example-Shop (example-shop.com)
**Report Type:** Final GRC Compliance Gap Report
**Assessment Timestamp:** 2026-09-27T20:10:23.852480+00:00
**Telemetry Collection Timestamp:** 2026-09-27T20:06:47.654273+00:00
**Policy Version Reviewed:** SEC-POL-v2.2 (effective 2026-09-27)
**Lead Auditor:** GRC Audit Function

---

## 1. Executive Summary

This report presents the combined findings of a two-part GRC assessment: (a) a textual alignment review of the E-Commerce Platform Security Policy (SEC-POL-v2.2) against a custom internal control baseline, and (b) a live technical telemetry review of the Cloudflare, Hostinger, WordPress, and WooCommerce environment supporting example-shop.com.

**Headline findings:**

- **Policy documentation** has improved substantially since the prior review cycle and now provides strong textual coverage of nearly all baseline controls. However, the policy's own Appendix of Open Items independently confirms that several controls are **written but not yet operational** (incident response plan not attached, asset inventory incomplete, alerting not configured, role-overlap not documented).
- **Live technical telemetry** confirms strong TLS/HTTPS enforcement at the Cloudflare edge but reveals that Cloudflare's `security_level` is set to `essentially_off`, materially weakening edge-layer threat detection.
- **A significant portion of the environment could not be verified at all.** WordPress, WooCommerce, and plugin/admin data collection attempts were blocked by a Cloudflare bot-challenge interstitial (HTTP 403), and the legacy Cloudflare WAF rules API returned an authentication error. These are **evidence gaps, not confirmed negative findings**, and are reported as **UNKNOWN** in accordance with audit rules.
- **WordPress core version could not be determined** from any available telemetry source and is explicitly reported as **UNKNOWN**.
- No payment gateway configuration was inspected or reported on, consistent with audit scope restrictions. This report makes **no claim of PCI DSS certification or NIST certification** of any kind.

This report should be read as a **conditional-pass, evidence-limited assessment**. Policy language is largely sound; operational and technical verification remains incomplete in several critical areas.

---

## 2. Scope and Methodology

### Scope
- SEC-POL-v2.2 policy document (textual alignment review)
- Live API-based telemetry from Cloudflare, Hostinger, WordPress, and WooCommerce for the domain `example-shop.com`
- Mapping of both to a custom internal control baseline

### Explicitly Out of Scope
- Payment gateway configuration (not inspected, not reported)
- Credentials, API keys, passwords, or WordPress application passwords (not exposed in this report)
- Formal PCI DSS assessment (SAQ/RoC) — this report is **not** a PCI DSS certification
- Formal NIST assessment — NIST does not certify organizations or e-commerce frameworks, and this report is **not** a NIST certification

### Methodology
1. Reviewed SEC-POL-v2.2 against each control in the custom baseline; classified each as Fully Addressed, Partially Addressed, or Addressed/Implementation Pending.
2. Collected live telemetry via API calls to Cloudflare, Hostinger, WordPress, and WooCommerce.
3. Cross-referenced telemetry results against baseline control requirements.
4. Where telemetry was missing, blocked, or errored, the corresponding control status was recorded as **UNKNOWN** rather than inferred as pass or fail, per audit rules.
5. A successful API call was **not** treated as evidence of compliance in itself; each response was evaluated for whether it actually demonstrated the control state.

### Baseline Disclosure
The control baseline used in this assessment is a **custom internal baseline**, informed by NIST CSF 2.0 and PCI DSS 4.0 principles, and tailored to a Cloudflare/Hostinger/WordPress/WooCommerce environment. **NIST does not publish or certify an official "e-commerce" framework**, and **no PCI SSC certification is claimed or implied** by this baseline or this report.

---

## 3. Environment Overview

| Component | Observed Detail | Source |
|---|---|---|
| Domain | example-shop.com | Hostinger API |
| Hosting | Hostinger, WordPress website type, main vhost | Hostinger API |
| Site created | 2026-08-23 | Hostinger API |
| CDN/Edge | Cloudflare (SSL mode: strict) | Cloudflare API |
| CMS | WordPress (core version: **UNKNOWN**) | WordPress API (blocked) |
| E-commerce platform | WooCommerce (version: **UNKNOWN**) | WooCommerce API (blocked) |
| PHP version | **UNKNOWN** | Hostinger API (404 — route not found) |

No further environment detail (server-level configuration, backup schedule, plugin list) could be established from telemetry and is reported as **UNKNOWN** below.

---

## 4. Policy Alignment Findings

SEC-POL-v2.2 was assessed against 25 baseline controls. Summary of outcomes:

| Status | Count | Example Controls |
|---|---|---|
| Fully Addressed | 16 | PR.AA-1, PR.AA-4, PR.DS-1, PR.PS-1, RS.MA-1, RC.RP-1, RC.CO-1 |
| Partially Addressed | 5 | ID.AM-1, PR.DS-2, PR.PS-2, PR.PS-4, GV.OC-1 (acknowledgement gap) |
| Addressed / Implementation Pending or Unverified | 4 | GV.RR-1, DE.AE-1, RS.AN-1, RS.MI-1, RS.CO-1 |

**Key gaps identified:**

1. **Incident Response Plan (IRP) not attached.** Three Critical-severity Respond-function controls (RS.AN-1, RS.MI-1, RS.CO-1) are incorporated by reference to an IRP that is currently a placeholder link in the policy Appendix. Until attached and reviewed, the organization's actual incident response capability is **unverifiable from policy text alone**.
2. **PCI attestation gap (PR.DS-2).** Section 5 mandates WooPayments hosted iFrames and prohibits raw cardholder data handling, but the policy does not require a formal PCI SAQ attestation or dedicated cardholder-data staff acknowledgement, distinct from general policy sign-off.
3. **BYOD/administrative backend restriction is procedural, not technically enforced (PR.PS-4).** Section 3 states a prohibition but does not mandate a technical control (e.g., Cloudflare Access device-posture policy) to enforce it.
4. **Role-overlap documentation outstanding (GV.RR-1).** The policy requires documentation when Security Lead and IT Lead are the same individual; the Appendix confirms this has not yet been produced.
5. **Alerting configuration outstanding (DE.AE-1).** Section 8 is well-drafted but the Appendix confirms alerting thresholds with the hosting/CDN provider have not yet been configured.
6. **Asset inventory incomplete (ID.AM-1).** The first full asset and software inventory required by Section 7 has not yet been completed, per the policy's own Appendix.

**Assessment:** Policy language closely tracks the baseline at a textual level. The residual risk is concentrated in **implementation and evidentiary maturity**, not drafting quality.

---

## 5. Live Environment Findings

Live telemetry was collected across Cloudflare, Hostinger, WordPress, and WooCommerce. Findings are summarized below; detailed per-platform findings follow in Sections 6–9.

| Area | Result |
|---|---|
| TLS/HTTPS enforcement | **Observed and confirmed active** (Cloudflare edge configuration) |
| Cloudflare threat-challenge sensitivity | **Observed as disabled/minimal** (`security_level = essentially_off`) |
| Cloudflare WAF custom rules | **UNKNOWN** — legacy API call failed authentication; newer Rulesets API not queried |
| WordPress core version, plugin inventory, admin count | **UNKNOWN** — blocked by Cloudflare bot-challenge interstitial (HTTP 403) |
| WooCommerce version/system status | **UNKNOWN** — blocked by same interstitial mechanism |
| PHP version | **UNKNOWN** — Hostinger API route returned 404 |
| Backup and auto-update configuration | **UNKNOWN** — no telemetry field present for this domain |

None of these UNKNOWN results should be interpreted as a confirmed absence of the underlying control. They reflect **collection failures at the edge or API level**, not verified negative findings.

---

## 6. Cloudflare Findings

### Observed Evidence
- `ssl_setting.value = "strict"`, certificate status `active`, no validation errors.
- `min_tls_version = "1.2"`.
- `always_use_https = "on"` (modified 2026-09-25).
- HSTS enabled: `max_age=31536000`, `include_subdomains=true`, `preload=false`.
- `security_level.value = "essentially_off"` (modified 2026-09-25).
- WAF custom rules query (legacy `firewall/rules` API): **HTTP 403, "Authentication error" (code 10000).**

### Assessment
- TLS/HTTPS enforcement (PR.DS-1) is **directly confirmed as active** via observed configuration. This is a positive finding based on actual evidence, not an assumption.
- The `security_level` setting of `essentially_off` is a **directly observed configuration weakness**. Per policy Section 8 and baseline control DE.AE-1, native CDN protective/alerting features must be actively configured, not left at default-off levels. This finding is rated **High severity**.
- **Cloudflare WAF rule status is explicitly UNKNOWN.** The legacy API call failed with an authentication error, and the platform note confirms this environment may use the newer Rulesets API instead. **This is stated explicitly per audit rules: a failed or absent API response does not prove the absence of WAF rules**, and no claim about WAF rule presence or effectiveness is made in either direction.
- A minor hardening opportunity (HSTS preload disabled) is noted as informational, not a compliance failure.

---

## 7. Hostinger Findings

### Observed Evidence
- One active website record: `example-shop.com`, type `wordpress`, enabled, created 2026-08-23.
- PHP details endpoint returned **HTTP 404** — route not found.

### Assessment
- The existence and basic enablement status of the hosting account is confirmed.
- **PHP version is UNKNOWN.** The API route attempted does not exist for this account/path combination; this is a **collection/API-path limitation**, not evidence that the PHP version is outdated or non-compliant.
- **Backup schedule and automatic update configuration are UNKNOWN** — no corresponding telemetry field was returned by any Hostinger API call in this collection cycle.

---

## 8. WordPress Findings

### Observed Evidence
- Plugin list query: **HTTP 403**, response body was a Cloudflare bot-challenge interstitial page ("Just a moment...") rather than WordPress API data.
- Administrator count query: **HTTP 403**, same interstitial pattern.

### Assessment
- **WordPress core version is UNKNOWN.** No telemetry source in this collection returned the core version, and the designated source for this data point (WooCommerce system_status) was itself blocked. This is stated explicitly as required.
- **Plugin inventory, plugin versions, and patch status are UNKNOWN.** The 403 response with interstitial HTML indicates the *collector* was challenged at the Cloudflare edge, not that the underlying WordPress data reflects any particular state.
- **Administrator account count is UNKNOWN**, for the same reason. No conclusion can be drawn regarding least-privilege posture (PR.AA-2) from this telemetry.
- These results represent an **audit-readiness/instrumentation gap**: the current telemetry pipeline cannot verify core security posture (patch currency, admin sprawl) without being challenged by the site's own edge protection.

---

## 9. WooCommerce Findings

### Observed Evidence
- `payment_verification: "disabled"` field was present in the raw telemetry payload but is **explicitly excluded from analysis and reporting** per audit scope restrictions on payment gateway configuration. No assessment, interpretation, or compliance judgment is made regarding this field.
- System status query: **HTTP 403**, same Cloudflare bot-challenge interstitial pattern as WordPress queries.

### Assessment
- **WooCommerce version is UNKNOWN.** The system_status endpoint, which would have provided this data, was blocked at the edge.
- No WooCommerce configuration data of any kind (other than the excluded payment field) was retrievable in this collection cycle.

---

## 10. NIST CSF 2.0 Alignment

The custom baseline maps controls to NIST CSF 2.0 functions (Govern, Identify, Protect, Detect, Respond, Recover). **This mapping is for internal risk-organization purposes only. NIST does not certify organizations, products, or e-commerce frameworks, and no such certification is claimed.**

| CSF 2.0 Function | Policy Alignment | Live Telemetry Verification |
|---|---|---|
| **Govern** | Strong textual coverage; role-overlap declaration pending | Not verifiable via technical telemetry (organizational control) |
| **Identify** | Moderate; inventory incomplete, no active scanning required | Partially verifiable — asset existence confirmed (Hostinger), but plugin/version inventory UNKNOWN |
| **Protect** | Strong; BYOD technical enforcement and PCI attestation gaps noted | TLS/HTTPS confirmed active; RBAC/admin data UNKNOWN |
| **Detect** | Strong textual coverage; alerting configuration pending | `security_level` observed disabled (High severity gap); WAF status UNKNOWN |
| **Respond** | Strong on paper; **unverified** pending IRP attachment | Not observable via technical telemetry |
| **Recover** | Strong | Not observable via technical telemetry |

---

## 11. Applicable Security-Control Considerations

The following control families from the custom baseline (informed by NIST CSF 2.0 and PCI DSS 4.0) are directly implicated by this assessment's findings:

- **PR.DS-1 (Data-in-Transit Encryption):** Confirmed operating as configured at time of collection.
- **DE.AE-1 (Anomalous Activity Detection):** Gap identified — Cloudflare `security_level` disabled.
- **DE.CM-1 (Continuous Monitoring):** WAF rule status unverifiable; logging layer status at application/identity level not observed.
- **GV.SC-1 / ID.AM-2 / PR.PS-1 (Plugin governance, inventory, patch management):** Cannot be verified from current telemetry; policy language is compliant but operating evidence is absent.
- **PR.AA-2 (Least Privilege):** Administrator count unverifiable; RBAC state UNKNOWN at the technical layer.
- **PR.DS-2 (Cardholder Data Protection):** Explicitly out of scope for this technical review; policy-level gap noted separately in Section 4. **No PCI DSS compliance or certification status is claimed.**

---

## 12. Telemetry Limitations

The following limitations apply globally to this report and constrain the conclusions that can be drawn:

1. **Cloudflare bot-challenge interference.** Multiple WordPress and WooCommerce API calls returned HTTP 403 with interstitial "Just a moment..." HTML instead of application data. This indicates the *telemetry collector* was challenged at the edge — it does **not** confirm or deny any state of the underlying application.
2. **Cloudflare WAF Rulesets not queried.** Only the legacy `firewall/rules` API was attempted, which failed authentication. The newer Rulesets API was not queried in this cycle. **WAF rule presence/absence is explicitly UNKNOWN and is not implied in either direction.**
3. **Hostinger PHP version endpoint unavailable.** The attempted API path returned 404. This is an API-path/routing issue, not a security finding.
4. **No backup, auto-update, IAM/IdP, MDM, or incident-response telemetry was collected** in this cycle. These controls remain **UNKNOWN** and require separate documentary or manual verification — their absence from this telemetry feed must not be interpreted as a control failure.
5. **A successful API response (e.g., Hostinger website list) confirms only the specific data returned** (e.g., site existence/enablement) and does not, by itself, establish compliance with any broader control.

---

## 13. Prioritized Remediation Plan

| Priority | Action | Related Control(s) | Source |
|---|---|---|---|
| 1 — High | Raise Cloudflare `security_level` from `essentially_off` to at least `medium`; document justification if intentionally lowered | DE.AE-1 | Live telemetry |
| 2 — High | Restore/allow-list telemetry collector access so WordPress, WooCommerce, plugin, and admin data can be verified going forward | GV.SC-1, ID.AM-2, PR.PS-1, PR.AA-2 | Live telemetry |
| 3 — Critical | Finalize and attach the Incident Response Plan; remove placeholder link | RS.AN-1, RS.MI-1, RS.CO-1 | Policy review |
| 4 — High | Add technical enforcement (e.g., Cloudflare Access device-posture policy) for administrative backend restriction, not policy statement alone | PR.PS-4 | Policy review |
| 5 — High | Add PCI SAQ attestation requirement and dedicated cardholder-data staff acknowledgement | PR.DS-2 | Policy review |
| 6 — Medium | Re-query Cloudflare Rulesets API with correctly scoped token to confirm WAF rule presence | DE.CM-1 | Live telemetry |
| 7 — Medium | Manually confirm PHP version and backup schedule via hPanel; add to asset inventory | PR.PS-1, ID.AM-1, RC.RP-1 | Live telemetry |
| 8 — Medium | Close outstanding Appendix items: role-overlap documentation, acknowledgement records, asset inventory completion, alert threshold configuration | GV.RR-1, GV.OC-1, ID.AM-1, DE.AE-1 | Policy review |
| 9 — Low | Enable HSTS preload once subdomain HTTPS support is confirmed | PR.DS-1 | Live telemetry |

---

## 14. Evidence/Retest Recommendations

1. **Retest WordPress/WooCommerce API access** after allow-listing the collector's IP or user-agent at the Cloudflare edge (or via a scoped bypass rule), to obtain WordPress core version, plugin inventory, patch status, WooCommerce version, and administrator count.
2. **Retest Cloudflare WAF configuration** using the Rulesets API (`/zones/{zone_id}/rulesets`) with an appropriately scoped API token, and manually cross-check in the Cloudflare dashboard.
3. **Retest Hostinger PHP version and backup configuration** via hPanel directly, since the attempted API route does not exist for this account.
4. **Collect and review the following documentary evidence** in a follow-up cycle, as none of it is observable via technical telemetry: IdP/SSO configuration and MFA enrollment report, offboarding tickets, RACI matrix or role-overlap declaration, asset and software inventory register, CVE feed subscription confirmation, 60-day access review logs, incident intake log, IRP document, and post-incident review records.
5. **Re-verify Cloudflare `security_level`** after remediation to confirm the setting was raised and documented.
6. Schedule the next full retest to align with the policy's 60-day access review cadence and annual policy review cycle.

---

## 15. Conclusion

SEC-POL-v2.2 demonstrates strong textual alignment with the organization's custom control baseline, itself informed by — but not certified against — NIST CSF 2.0 and PCI DSS 4.0 principles. The policy's own Appendix of Open Items transparently acknowledges that several controls remain unimplemented, which this audit independently corroborates.

Live technical telemetry confirms that TLS/HTTPS enforcement is correctly configured at the Cloudflare edge, but identifies a **High-severity gap** in Cloudflare's threat-challenge sensitivity (`security_level` set to `essentially_off`). Critically, a substantial portion of the WordPress, WooCommerce, and Cloudflare WAF environment **could not be verified at all** due to edge-layer bot-challenge interference and API authentication/routing failures. These are reported strictly as **UNKNOWN**, consistent with the principle that missing or blocked telemetry must never be treated as evidence of either compliance or non-compliance.

This report does **not** constitute a PCI DSS certification, a NIST certification, or a formal compliance attestation of any kind. It represents a point-in-time assessment against a custom internal baseline, intended to guide prioritized remediation and to establish a foundation for improved telemetry access and evidentiary completeness in future audit cycles.

---

## 16. Auditor Addendum — Post-Collection Verification

*Added after initial report generation, prior to publication. Automated telemetry is a snapshot; the items below reflect verification performed after that snapshot was taken and supersede the corresponding findings above.*

### 16.1 Correction: Cloudflare `security_level` finding overstated

Section 6 and the Conclusion above rate `security_level = essentially_off` as a **High-severity** finding, based on treating "security level" as a graduated edge-protection dial (off/low/medium/high) that was materially weakening threat mitigation.

Cloudflare has since restructured this setting. Per current Cloudflare documentation, `security_level` in the modern security dashboard and API now controls **only Under Attack Mode** (a DDoS-specific challenge mode) — it is no longer a general-purpose threat-sensitivity dial. `essentially_off` therefore indicates only that Under Attack Mode is disabled, which is the **expected, normal state** for a site that is not currently experiencing a DDoS event.

**Revised assessment:** This finding is downgraded from **High** to **Informational**. General edge protection for this environment is governed by WAF managed/custom rules (see 16.2 below), not by `security_level`. No remediation action is required on this item beyond documenting the corrected interpretation. Auditors should independently verify vendor-specific control semantics rather than relying on legacy field names, since providers periodically redefine what a setting actually does — this report's Priority 1 remediation item is withdrawn accordingly.

### 16.2 Update: WAF custom rules manually confirmed present

Section 6 and the Telemetry Limitations section correctly report WAF rule presence as **UNKNOWN**, since the legacy `firewall/rules` API (deprecated by Cloudflare in June 2025) returned an authentication error and the newer Rulesets API was not queried in this collection cycle.

**Manual verification (Cloudflare dashboard, post-collection):** 5 custom WAF rules are configured and active on this zone, consistent with the Cloudflare Free plan's custom-rule allowance. This closes remediation item 6 ("Re-query Cloudflare Rulesets API... to confirm WAF rule presence"). Recommended follow-up: query the Rulesets API directly in a future automated cycle so this no longer requires manual confirmation.

### 16.3 Update: Incident Response Plan attached

Section 4 and remediation item 3 (Critical) identify the Incident Response Plan as referenced by policy but not attached, existing only as a placeholder link.

**Status update:** The Incident Response Plan has been finalized and attached; SEC-POL-v2.2, Section 6 now links to the controlled document rather than a placeholder. This closes remediation item 3. Controls RS.AN-1, RS.MI-1, and RS.CO-1 should be re-assessed as **Fully Addressed** on the next review cycle, pending confirmation that the attached IRP's content meets the minimum elements specified in policy Section 6.

### 16.4 Observation: Edge protection is now blocking the audit tooling itself

Sections 8 and 9 report WordPress and WooCommerce telemetry collection as blocked by a Cloudflare bot-challenge interstitial (HTTP 403) rather than reaching the application layer at all. Notably, this occurred *after* HTTPS enforcement and WAF rules were put in place — meaning the site's own hardening is now intercepting this audit tool's automated requests before WordPress application-layer authentication is ever evaluated.

This is not a control failure; if anything, it is a secondary, informal signal that edge-layer bot mitigation is functioning as intended against unauthenticated-looking automated traffic. It does, however, mean this collection method needs a scoped exception (e.g., an allow-list rule for the collector's source, or a dedicated service-token bypass) to restore visibility into WordPress/WooCommerce telemetry in future cycles — see Evidence/Retest Recommendation 1.

### Net effect of this addendum

- Priority 1 (security level) — **withdrawn**, reclassified as informational
- Priority 3 (IRP) — **closed**
- Priority 6 (WAF verification) — **closed** via manual verification; automated re-query still recommended
- All other findings in this report stand as originally assessed.
