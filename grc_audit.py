"""
GRC Automated Audit Pipeline - Claude Edition
==============================================

Two-phase audit:

Phase A - Policy Alignment Review
    Compares company_security_policy.txt against:
      - NIST CSF 2.0
      - PCI DSS 4.0

Phase B - Live Environment Standing Check
    Collects telemetry from:
      - Cloudflare
      - Hostinger
      - WordPress
      - WooCommerce

The final Claude report identifies:
      - policy gaps
      - live-environment gaps
      - control coverage
      - telemetry limitations
      - recommended remediation actions

IMPORTANT:
NIST does not publish a framework literally called "NIST E-Commerce 2.0".

This script uses a custom control baseline informed by:
      - NIST CSF 2.0
      - PCI DSS 4.0

The baseline is interpreted for a:
      - Cloudflare
      - Hostinger
      - WordPress
      - WooCommerce

environment.

This is an internal GRC assessment tool, not a certification tool.

Payment gateway/payment-processing verification is intentionally NOT
performed by this script.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import anthropic
import markdown
import requests

# Optional: load a local .env file if python-dotenv is installed.
# This is purely a convenience for local development so credentials don't
# need to be re-exported into the shell every session. It has zero effect
# on production/CI environments, which set real environment variables.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


# =============================================================================
# CONFIGURATION
# =============================================================================

POLICY_FILE = "SEC-POL-v2.2.md"
CONTROLS_FILE = "grc_control_baseline.json"
REPORT_STATIC = "GRC_Compliance_Gap_Report.md"
REPORT_HTML = "GRC_Compliance_Gap_Report.html"


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")

# Current Claude model.
# Can be overridden with the CLAUDE_MODEL environment variable.
CLAUDE_MODEL = os.environ.get(
    "CLAUDE_MODEL",
    "claude-sonnet-5",
)

CLAUDE_MAX_TOKENS = int(
    os.environ.get(
        "CLAUDE_MAX_TOKENS",
        "16000",
    )
)

# ---------------------------------------------------------------------------
# Cloudflare
# ---------------------------------------------------------------------------

CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
CF_ZONE_ID = os.environ.get("CF_ZONE_ID")

# ---------------------------------------------------------------------------
# Hostinger
# ---------------------------------------------------------------------------

HOSTINGER_API_TOKEN = os.environ.get(
    "HOSTINGER_API_TOKEN"
)

HOSTINGER_USERNAME = os.environ.get(
    "HOSTINGER_USERNAME"
)


# Note: unlike WP_BASE_URL, this is used as a path *segment* in the
# Hostinger API (e.g. .../websites/{HOSTINGER_DOMAIN}/php/details), not
# as a request URL on its own, so it should be a bare domain with no
# http:// or https:// prefix.
HOSTINGER_DOMAIN = os.environ.get(
    "HOSTINGER_DOMAIN"
)

# ---------------------------------------------------------------------------
# WordPress
# ---------------------------------------------------------------------------

def normalize_base_url(url):
    """
    Ensure a URL has an explicit scheme.

    Without this, a value like WP_BASE_URL=example.com (no http:// or
    https://) causes every `requests` call built from it to fail with
    `MissingSchema`, which is indistinguishable from a real outage in
    the logs. Normalizing here means the fix lives in one place instead
    of depending on whoever sets the environment variable remembering
    to type the scheme correctly.
    """
    url = (url or "").strip().rstrip("/")

    if not url:
        return url

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    return url


WP_BASE_URL = normalize_base_url(
    os.environ.get("WP_BASE_URL", "")
)

WP_USER = os.environ.get("WP_USER")

WP_APPLICATION_PASS = os.environ.get(
    "WP_APP_PASS"
)


# =============================================================================
# GENERAL HELPERS
# =============================================================================

def utc_now():
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def log_error(context, exc):
    """Print a useful error containing exception type and message."""
    print(
        f"[ERROR] {context}: "
        f"{type(exc).__name__}: {exc}",
        file=sys.stderr,
    )


def ensure_file_exists(path):
    """Fail clearly when a required local file is missing."""
    if not Path(path).is_file():
        raise FileNotFoundError(
            f"Required file not found: {path}"
        )


def safe_json_response(response):
    """
    Parse a response as JSON.

    If the response is not valid JSON, return a structured error instead.
    """
    try:
        return response.json()

    except ValueError:
        return {
            "error": "invalid_json_response",
            "http_status": response.status_code,
            "body": response.text[:1000],
        }


def api_error(response):
    """Return a concise structured API error."""
    return {
        "http_status": response.status_code,
        "error": safe_json_response(response),
    }


# =============================================================================
# CREDENTIAL VALIDATION
# =============================================================================

def check_sources():
    """
    Display which telemetry sources are configured.

    Secrets are never printed.
    """

    sources = {
        "cloudflare": bool(
            CF_API_TOKEN
            and CF_ZONE_ID
        ),

        "hostinger": bool(
            HOSTINGER_API_TOKEN
            and HOSTINGER_USERNAME
            and HOSTINGER_DOMAIN
        ),

        "wordpress": bool(
            WP_BASE_URL
            and WP_USER
            and WP_APPLICATION_PASS
        ),
    }

    print("\n--- Telemetry source configuration ---")

    for name, configured in sources.items():
        status = (
            "CONFIGURED"
            if configured
            else "MISSING"
        )

        print(
            f"  {name:12s}: {status}"
        )

    print("---------------------------------------\n")

    return sources


def validate_credentials():
    """
    Fail fast when required environment variables are missing.

    This prevents the audit from running with incomplete credentials and
    producing a misleading report.
    """

    required = {
        "ANTHROPIC_API_KEY": ANTHROPIC_API_KEY,

        "CF_API_TOKEN": CF_API_TOKEN,
        "CF_ZONE_ID": CF_ZONE_ID,

        "HOSTINGER_API_TOKEN": HOSTINGER_API_TOKEN,
        "HOSTINGER_USERNAME": HOSTINGER_USERNAME,
        "HOSTINGER_DOMAIN": HOSTINGER_DOMAIN,

        "WP_BASE_URL": WP_BASE_URL,
        "WP_USER": WP_USER,
        "WP_APP_PASS": WP_APPLICATION_PASS,
    }

    missing = [
        name
        for name, value in required.items()
        if not value
    ]

    if missing:
        print(
            "\n[FATAL] Missing required environment variables:\n"
        )

        for name in missing:
            print(
                f"  - {name}"
            )

        print(
            "\nSet the missing variables before running the audit."
        )

        raise RuntimeError(
            "Required credentials are missing: "
            + ", ".join(missing)
        )

    print(
        "[OK] Required credentials are present."
    )


# =============================================================================
# CLOUDFLARE TELEMETRY
# =============================================================================

def fetch_cloudflare_telemetry():
    """
    Collect Cloudflare security telemetry.

    Collects:
      - SSL mode
      - minimum TLS version
      - security level
      - Always Use HTTPS
      - HSTS/security headers
      - legacy custom firewall rules

    The firewall rules endpoint is best-effort because newer Cloudflare
    deployments may use the Rulesets API.
    """

    if not (
        CF_API_TOKEN
        and CF_ZONE_ID
    ):
        return {
            "status": "skipped_missing_credentials"
        }

    headers = {
        "Authorization": (
            f"Bearer {CF_API_TOKEN}"
        ),
        "Content-Type": "application/json",
    }

    telemetry = {
        "collected_at": utc_now(),
    }

    endpoints = {
        "ssl_setting": "settings/ssl",
        "min_tls_version": "settings/min_tls_version",
        "security_level": "settings/security_level",
        "always_use_https": "settings/always_use_https",
        "security_header_hsts": "settings/security_header",
    }

    for key, path in endpoints.items():

        try:
            response = requests.get(
                (
                    "https://api.cloudflare.com/client/v4/"
                    f"zones/{CF_ZONE_ID}/{path}"
                ),
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                data = safe_json_response(
                    response
                )

                if isinstance(data, dict):
                    telemetry[key] = data.get(
                        "result",
                        {},
                    )
                else:
                    telemetry[key] = data

            else:
                telemetry[key] = api_error(
                    response
                )

        except requests.RequestException as exc:
            telemetry[key] = {
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

    # -----------------------------------------------------------------------
    # Legacy Cloudflare firewall rules
    # -----------------------------------------------------------------------

    try:
        response = requests.get(
            (
                "https://api.cloudflare.com/client/v4/"
                f"zones/{CF_ZONE_ID}/firewall/rules"
            ),
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            data = safe_json_response(
                response
            )

            if isinstance(data, dict):
                telemetry["waf_custom_rules"] = data.get(
                    "result",
                    [],
                )
            else:
                telemetry["waf_custom_rules"] = data

        else:
            telemetry["waf_custom_rules"] = api_error(
                response
            )

    except requests.RequestException as exc:
        telemetry["waf_custom_rules"] = {
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    telemetry["_note"] = (
        "Cloudflare deployments may use the newer Rulesets API "
        "instead of the legacy firewall/rules endpoint. An empty "
        "or failed legacy endpoint does not prove that no WAF rules "
        "exist. Verify Cloudflare WAF Rulesets manually when needed."
    )

    return telemetry


# =============================================================================
# HOSTINGER TELEMETRY
# =============================================================================

def fetch_hostinger_telemetry():
    """
    Collect hosting-level telemetry from Hostinger.

    Focus:
      - websites
      - PHP configuration
      - PHP version/support information
    """

    if not (
        HOSTINGER_API_TOKEN
        and HOSTINGER_USERNAME
        and HOSTINGER_DOMAIN
    ):
        return {
            "status": "skipped_missing_credentials"
        }

    headers = {
        "Authorization": (
            f"Bearer {HOSTINGER_API_TOKEN}"
        ),
        "Accept": "application/json",
    }

    telemetry = {
        "collected_at": utc_now(),
    }

    # -----------------------------------------------------------------------
    # Websites
    # -----------------------------------------------------------------------

    try:
        response = requests.get(
            (
                "https://developers.hostinger.com/"
                "api/hosting/v1/websites"
            ),
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            telemetry["websites"] = (
                safe_json_response(response)
            )

        else:
            telemetry["websites_error"] = api_error(
                response
            )

    except requests.RequestException as exc:
        telemetry["websites_error"] = {
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    # -----------------------------------------------------------------------
    # PHP details
    # -----------------------------------------------------------------------

    try:
        response = requests.get(
            (
                "https://developers.hostinger.com/"
                "api/hosting/v1/accounts/"
                f"{HOSTINGER_USERNAME}/"
                f"websites/{HOSTINGER_DOMAIN}/"
                "php/details"
            ),
            headers=headers,
            timeout=10,
        )

        if response.status_code == 200:
            telemetry["php_details"] = (
                safe_json_response(response)
            )

        else:
            telemetry["php_details_error"] = api_error(
                response
            )

    except requests.RequestException as exc:
        telemetry["php_details_error"] = {
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    telemetry["_note"] = (
        "Hostinger's API may not expose every hosting security "
        "setting. Cross-check PHP version, automatic updates, "
        "and backup configuration in hPanel when necessary."
    )

    return telemetry


# =============================================================================
# WORDPRESS TELEMETRY
# =============================================================================

def fetch_wordpress_telemetry():
    """
    Collect WordPress application-level telemetry.

    Collects:
      - installed plugins
      - plugin versions/status
      - administrator count
      - administrator usernames/slugs

    WordPress core version is NOT inferred from X-WP-Total.
    """

    if not (
        WP_BASE_URL
        and WP_USER
        and WP_APPLICATION_PASS
    ):
        return {
            "status": "skipped_missing_credentials"
        }

    telemetry = {
        "collected_at": utc_now(),
    }

    auth = (
        WP_USER,
        WP_APPLICATION_PASS,
    )

    # -----------------------------------------------------------------------
    # Plugins
    # -----------------------------------------------------------------------

    try:
        response = requests.get(
            f"{WP_BASE_URL}/wp-json/wp/v2/plugins",
            auth=auth,
            timeout=10,
        )

        if response.status_code == 200:
            plugins = safe_json_response(
                response
            )

            if isinstance(plugins, list):

                telemetry["plugins"] = [
                    {
                        "name": plugin.get("name"),
                        "status": plugin.get("status"),
                        "version": plugin.get("version"),
                        "plugin": plugin.get("plugin"),
                    }
                    for plugin in plugins
                ]

            else:
                telemetry["plugins_error"] = plugins

        else:
            telemetry["plugins_error"] = api_error(
                response
            )

    except requests.RequestException as exc:
        telemetry["plugins_error"] = {
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    # -----------------------------------------------------------------------
    # Administrators
    # -----------------------------------------------------------------------

    try:
        response = requests.get(
            f"{WP_BASE_URL}/wp-json/wp/v2/users",
            params={
                "roles": "administrator",
                "per_page": 100,
            },
            auth=auth,
            timeout=10,
        )

        if response.status_code == 200:
            users = safe_json_response(
                response
            )

            if isinstance(users, list):

                telemetry["admin_count"] = len(
                    users
                )

                telemetry["admin_usernames"] = [
                    user.get("slug")
                    for user in users
                    if user.get("slug")
                ]

            else:
                telemetry["admin_count_error"] = users

        else:
            telemetry["admin_count_error"] = api_error(
                response
            )

    except requests.RequestException as exc:
        telemetry["admin_count_error"] = {
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    telemetry["_note"] = (
        "WordPress core version is not inferred from X-WP-Total. "
        "That header represents collection pagination/count information. "
        "The WordPress core version is obtained from WooCommerce "
        "system_status when available."
    )

    return telemetry


# =============================================================================
# WOOCOMMERCE TELEMETRY
# =============================================================================

def fetch_woocommerce_telemetry():
    """
    Collect general WooCommerce platform telemetry.

    This function does NOT inspect or verify:

      - payment gateways
      - payment gateway credentials
      - payment configuration
      - payment processing configuration
      - enabled payment gateways

    It only collects general application/platform information such as:

      - WordPress version
      - WooCommerce version
      - PHP version
      - database information
      - security information
      - active plugins
      - theme
    """

    if not (
        WP_BASE_URL
        and WP_USER
        and WP_APPLICATION_PASS
    ):
        return {
            "status": "skipped_missing_credentials"
        }

    telemetry = {
        "collected_at": utc_now(),
        "payment_verification": "disabled",
    }

    auth = (
        WP_USER,
        WP_APPLICATION_PASS,
    )

    try:
        response = requests.get(
            (
                f"{WP_BASE_URL}/wp-json/"
                "wc/v3/system_status"
            ),
            auth=auth,
            timeout=15,
        )

        if response.status_code != 200:
            telemetry["system_status_error"] = api_error(
                response
            )

            return telemetry

        data = safe_json_response(
            response
        )

        if not isinstance(data, dict):
            telemetry["system_status_error"] = {
                "error": "unexpected_response_format"
            }

            return telemetry

        environment = data.get(
            "environment",
            {},
        )

        telemetry["environment"] = environment

        telemetry["security"] = data.get(
            "security",
            {},
        )

        telemetry["active_plugins"] = data.get(
            "active_plugins",
            [],
        )

        telemetry["theme"] = data.get(
            "theme",
            {},
        )

        telemetry["database"] = data.get(
            "database",
            {},
        )

        # ---------------------------------------------------------------
        # Useful platform versions
        # ---------------------------------------------------------------

        telemetry["wp_version"] = environment.get(
            "wp_version",
            "Unknown",
        )

        telemetry["woocommerce_version"] = environment.get(
            "version",
            "Unknown",
        )

        telemetry["php_version"] = environment.get(
            "php_version",
            "Unknown",
        )

    except requests.RequestException as exc:
        telemetry["system_status_error"] = {
            "error_type": type(exc).__name__,
            "error": str(exc),
        }

    telemetry["_note"] = (
        "Payment verification is intentionally disabled. "
        "WooCommerce system status is collected only for general "
        "WordPress, WooCommerce, PHP, database, plugin, theme, "
        "and security posture information."
    )

    return telemetry


# =============================================================================
# TELEMETRY COLLECTION
# =============================================================================

def collect_all_telemetry():
    """Collect telemetry from all configured systems."""

    print(
        "\n============================================================"
    )
    print(
        "COLLECTING LIVE TELEMETRY"
    )
    print(
        "============================================================"
    )

    telemetry = {
        "collected_at": utc_now(),
        "cloudflare": {},
        "hostinger": {},
        "wordpress": {},
        "woocommerce": {},
    }

    collectors = {
        "cloudflare": fetch_cloudflare_telemetry,
        "hostinger": fetch_hostinger_telemetry,
        "wordpress": fetch_wordpress_telemetry,
        "woocommerce": fetch_woocommerce_telemetry,
    }

    for name, collector in collectors.items():

        print(
            f"[+] Collecting {name}..."
        )

        try:
            telemetry[name] = collector()

        except Exception as exc:

            log_error(
                f"Telemetry collector '{name}' failed",
                exc,
            )

            telemetry[name] = {
                "status": "collector_error",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }

    print(
        "[OK] Telemetry collection complete."
    )

    return telemetry


# =============================================================================
# LOCAL CONTROL BASELINE
# =============================================================================

def load_policy():
    """Load the company security policy."""
    ensure_file_exists(
        POLICY_FILE
    )

    return Path(
        POLICY_FILE
    ).read_text(
        encoding="utf-8"
    )


def load_controls():
    """Load the custom GRC control baseline."""
    ensure_file_exists(
        CONTROLS_FILE
    )

    with open(
        CONTROLS_FILE,
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


# =============================================================================
# CLAUDE CLIENT
# =============================================================================

def create_claude_client():
    """Create the Anthropic API client."""

    if not ANTHROPIC_API_KEY:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not configured."
        )

    return anthropic.Anthropic(
        api_key=ANTHROPIC_API_KEY
    )


def extract_claude_text(response):
    """Extract text blocks from an Anthropic response."""

    parts = []

    for block in getattr(
        response,
        "content",
        [],
    ):

        if getattr(
            block,
            "type",
            None,
        ) == "text":

            parts.append(
                block.text
            )

    return "\n".join(
        parts
    ).strip()


def call_claude(
    prompt,
    max_tokens=CLAUDE_MAX_TOKENS,
):
    """
    Send a prompt to Claude and return the generated text.

    Errors are logged and re-raised so failures cannot be silently ignored.
    """

    client = create_claude_client()

    try:

        response = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=max_tokens,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        text = extract_claude_text(
            response
        )

        if not text:
            raise RuntimeError(
                "Claude returned no text content."
            )

        return text

    except Exception as exc:

        log_error(
            (
                "Claude API call failed using "
                f"model '{CLAUDE_MODEL}'"
            ),
            exc,
        )

        raise


# =============================================================================
# CONTROL FILE REFRESH
# =============================================================================

def refresh_control_file(
    policy_text,
    controls,
):
    """Ask Claude to update the local GRC control baseline."""

    print(
        "\n--- Refreshing GRC control baseline ---"
    )

    prompt = f"""
You are a senior GRC architect.

Review the company security policy and existing custom control baseline.

Update the control baseline so it remains aligned with:

1. NIST Cybersecurity Framework 2.0:
   - Govern
   - Identify
   - Protect
   - Detect
   - Respond
   - Recover

2. PCI DSS 4.0, where relevant.

The environment is:

- Cloudflare
- Hostinger
- WordPress
- WooCommerce

Important:

NIST does not publish an official "e-commerce 2.0" framework.

Do not claim that this custom baseline is an official NIST certification.

Return ONLY valid JSON.

The JSON must contain:

{{
  "controls": [...]
}}

Each control should contain:

- id
- title
- framework
- category
- requirement
- evidence_sources
- severity

Existing baseline:

{json.dumps(controls, indent=2)}

Company policy:

--- BEGIN COMPANY POLICY ---
{policy_text}
--- END COMPANY POLICY ---
"""

    response_text = call_claude(
        prompt,
        max_tokens=12000,
    )

    cleaned = response_text.strip()

    # Remove Markdown code fences if Claude adds them.
    if cleaned.startswith("```"):

        cleaned = cleaned.replace(
            "```json",
            "",
            1,
        )

        cleaned = cleaned.replace(
            "```",
            "",
        ).strip()

    try:

        updated_controls = json.loads(
            cleaned
        )

    except json.JSONDecodeError as exc:

        raise ValueError(
            "Claude returned invalid JSON while "
            "refreshing the control baseline."
        ) from exc

    if not isinstance(
        updated_controls,
        dict,
    ):
        raise ValueError(
            "Claude returned JSON, but the top-level "
            "value was not an object."
        )

    if not isinstance(
        updated_controls.get("controls"),
        list,
    ):
        raise ValueError(
            "Claude control baseline does not contain "
            "a valid 'controls' array."
        )

    with open(
        CONTROLS_FILE,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            updated_controls,
            handle,
            indent=2,
            ensure_ascii=False,
        )

    print(
        f"[OK] Updated {CONTROLS_FILE}"
    )

    return updated_controls


# =============================================================================
# PHASE A - POLICY ALIGNMENT
# =============================================================================

def run_policy_alignment(
    policy_text,
    controls,
):
    """Compare the written policy against the control baseline."""

    print(
        "\n============================================================"
    )
    print(
        "PHASE A - POLICY ALIGNMENT REVIEW"
    )
    print(
        "============================================================"
    )

    prompt = f"""
You are a senior GRC auditor.

Perform a policy alignment review.

Compare the company's security policy against the supplied custom
control baseline informed by:

- NIST CSF 2.0
- PCI DSS 4.0

The baseline is customized for:

- Cloudflare
- Hostinger
- WordPress
- WooCommerce

Do not claim that NIST certifies this custom baseline.

For each relevant control, determine:

- whether the policy addresses it
- what policy language supports it
- what is missing
- what is ambiguous
- what should be added
- severity

Return a detailed Markdown section suitable for a GRC report.

Do not invent policy statements that are not present.

--- BEGIN POLICY ---
{policy_text}
--- END POLICY ---

--- BEGIN CONTROL BASELINE ---
{json.dumps(controls, indent=2)}
--- END CONTROL BASELINE ---
"""

    return call_claude(
        prompt,
        max_tokens=CLAUDE_MAX_TOKENS,
    )


# =============================================================================
# PHASE B - LIVE ENVIRONMENT REVIEW
# =============================================================================

def run_live_environment_review(
    policy_text,
    controls,
    telemetry,
):
    """Compare live telemetry against policy and controls."""

    print(
        "\n============================================================"
    )
    print(
        "PHASE B - LIVE ENVIRONMENT STANDING CHECK"
    )
    print(
        "============================================================"
    )

    prompt = f"""
You are a senior security auditor performing a live-environment
GRC assessment.

Compare the live telemetry against:

1. The company's written security policy.
2. The custom control baseline informed by:
   - NIST CSF 2.0
   - PCI DSS 4.0

Environment:

- Cloudflare
- Hostinger
- WordPress
- WooCommerce

The telemetry may be incomplete.

Do NOT assume missing telemetry means that a control is absent.

Use these statuses:

- PASS: evidence supports the control
- FAIL: evidence contradicts the control
- PARTIAL: evidence is incomplete
- UNKNOWN: telemetry cannot establish the answer
- NOT APPLICABLE: control does not apply

For important findings provide:

- control
- observed evidence
- expected state
- gap
- severity
- remediation
- evidence limitation

Pay attention to:

- Cloudflare TLS configuration
- HTTPS enforcement
- HSTS
- Cloudflare security level
- WAF/custom rules
- PHP version
- WordPress version
- WooCommerce version
- plugin versions
- administrator count
- security configuration
- backup/update evidence

IMPORTANT:

Do NOT inspect, verify, evaluate, or report on:

- payment gateway configuration
- payment gateway credentials
- payment processing configuration
- enabled payment gateways

Do not invent values.

Do not treat an unavailable API field as proof that the underlying
security control is absent.

--- BEGIN COMPANY POLICY ---
{policy_text}
--- END COMPANY POLICY ---

--- BEGIN CONTROL BASELINE ---
{json.dumps(controls, indent=2)}
--- END CONTROL BASELINE ---

--- BEGIN LIVE TELEMETRY ---
{json.dumps(telemetry, indent=2)}
--- END LIVE TELEMETRY ---
"""

    return call_claude(
        prompt,
        max_tokens=CLAUDE_MAX_TOKENS,
    )


# =============================================================================
# FINAL REPORT
# =============================================================================

def generate_audit_report(
    policy_text,
    controls,
    telemetry,
    policy_review,
    live_review,
):
    """Generate the final consolidated Markdown report."""

    print(
        "\n============================================================"
    )
    print(
        "GENERATING FINAL AUDIT REPORT"
    )
    print(
        "============================================================"
    )

    prompt = f"""
You are the lead GRC auditor.

Create a professional final GRC Compliance Gap Report.

Include:

1. Executive summary
2. Scope and methodology
3. Environment overview
4. Policy alignment findings
5. Live environment findings
6. Cloudflare findings
7. Hostinger findings
8. WordPress findings
9. WooCommerce findings
10. NIST CSF 2.0 alignment
11. Applicable security-control considerations
12. Telemetry limitations
13. Prioritized remediation plan
14. Evidence/retest recommendations
15. Conclusion

Use Markdown.

Reporting rules:

- Never invent evidence.
- Clearly distinguish observed evidence from assumptions.
- Missing telemetry means UNKNOWN unless other evidence establishes
  the control state.
- Do not claim compliance merely because an API call succeeded.
- Do not claim PCI DSS certification.
- Do not claim NIST certification.
- Explain that the baseline is a custom baseline informed by
  NIST CSF 2.0 and PCI DSS 4.0.
- Where Cloudflare WAF data is incomplete, explicitly say so.
- Where WordPress core version is unavailable, explicitly say UNKNOWN.
- Do not expose credentials, API keys, passwords, or application passwords.
- Do not inspect or report on payment gateway configuration.

Assessment timestamp:

{utc_now()}

--- COMPANY POLICY ---
{policy_text}

--- CONTROL BASELINE ---
{json.dumps(controls, indent=2)}

--- LIVE TELEMETRY ---
{json.dumps(telemetry, indent=2)}

--- POLICY ALIGNMENT REVIEW ---
{policy_review}

--- LIVE ENVIRONMENT REVIEW ---
{live_review}
"""

    return call_claude(
        prompt,
        max_tokens=CLAUDE_MAX_TOKENS,
    )


# =============================================================================
# HTML REPORT RENDERING
# =============================================================================
#
# The audit's real output is the Markdown report (REPORT_STATIC) — it's
# plain text, diffs cleanly in git, and is what you should compare across
# runs. This section additionally renders that same Markdown into a
# styled, easy-to-read HTML file (REPORT_HTML) purely for human reading —
# open it in a browser instead of scrolling through raw Markdown.

# The live-environment review prompt instructs Claude to use these exact
# status words, so highlighting them as colored badges is reliable rather
# than guesswork. Longer/more specific phrases are listed first so they
# match before their shorter substrings do.
_STATUS_BADGES = [
    (r"CONFIRMED FAILURE", "fail"),
    (r"CONFIRMED WEAKNESS", "weak"),
    (r"NOT APPLICABLE", "scope"),
    (r"PARTIAL", "weak"),
    (r"UNKNOWN", "unknown"),
    (r"FAIL", "fail"),
    (r"PASS", "pass"),
]

_STATUS_RE = re.compile(
    r"\b(" + "|".join(pattern for pattern, _ in _STATUS_BADGES) + r")\b"
)


def _status_badge_replacer(match):
    """Wrap a matched status keyword in a colored badge span."""
    text = match.group(0)

    for pattern, css_class in _STATUS_BADGES:
        if re.fullmatch(pattern, text, flags=re.IGNORECASE):
            return f'<span class="badge badge-{css_class}">{text}</span>'

    return text


def add_status_badges(html_body):
    """Highlight PASS/FAIL/PARTIAL/UNKNOWN/NOT APPLICABLE as colored badges."""
    return _STATUS_RE.sub(_status_badge_replacer, html_body)


_REPORT_CSS = """
:root{
  --bg:#F5F6F8; --surface:#FFFFFF; --ink:#1C232E; --ink-soft:#525B68;
  --rule:#E1E4E9; --accent:#2A4A6B;
  --fail:#A2392B; --fail-bg:#FBECE9;
  --weak:#A16A15; --weak-bg:#FBF1DE;
  --unknown:#5B6472; --unknown-bg:#EEF0F2;
  --pass:#2C6B4F; --pass-bg:#E9F3EE;
  --scope:#4A5568; --scope-bg:#EEF0F3;
}
*{box-sizing:border-box;}
body{
  background:var(--bg); color:var(--ink); margin:0;
  font-family:"IBM Plex Sans",Arial,Helvetica,sans-serif;
  font-size:16px; line-height:1.6;
}
.page{max-width:880px; margin:0 auto; padding:48px 24px 96px;}
h1,h2,h3,h4{
  font-family:"Source Serif 4",Georgia,"Times New Roman",serif;
  font-weight:600; color:var(--ink); margin:32px 0 12px;
}
h1{font-size:32px; border-bottom:3px solid var(--accent); padding-bottom:12px;}
h2{font-size:22px; border-bottom:1px solid var(--rule); padding-bottom:8px;}
h3{font-size:18px;}
p{margin:0 0 14px;}
ul,ol{padding-left:22px;}
li{margin-bottom:6px;}
table{width:100%; border-collapse:collapse; margin:16px 0; background:var(--surface); border:1px solid var(--rule);}
th,td{text-align:left; padding:10px 12px; border-bottom:1px solid var(--rule); vertical-align:top; font-size:14.5px;}
th{background:#EFF1F4; font-weight:600; color:var(--ink-soft);}
tr:last-child td{border-bottom:none;}
code{background:#EFF1F4; padding:1px 5px; border-radius:2px; font-size:0.9em;}
pre{background:#1C232E; color:#EAEDF1; padding:14px; overflow-x:auto; border-radius:3px;}
pre code{background:none; color:inherit;}
blockquote{
  border-left:4px solid var(--accent); margin:16px 0; padding:8px 16px;
  background:var(--surface); color:var(--ink-soft);
}
hr{border:none; border-top:1px solid var(--rule); margin:32px 0;}
.badge{
  display:inline-block; padding:2px 9px; border-radius:2px;
  font-size:12.5px; font-weight:600; white-space:nowrap;
}
.badge-fail{background:var(--fail-bg); color:var(--fail);}
.badge-weak{background:var(--weak-bg); color:var(--weak);}
.badge-unknown{background:var(--unknown-bg); color:var(--unknown);}
.badge-pass{background:var(--pass-bg); color:var(--pass);}
.badge-scope{background:var(--scope-bg); color:var(--scope);}
"""


def render_html_report(markdown_text):
    """
    Convert the Markdown audit report into a styled, standalone HTML file.

    This is a read-only presentation layer over the same content in
    REPORT_STATIC — it does not change what was found, only how it's
    displayed.
    """
    body_html = markdown.markdown(
        markdown_text,
        extensions=["tables", "fenced_code", "sane_lists"],
    )
    body_html = add_status_badges(body_html)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GRC Compliance Gap Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Source+Serif+4:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>{_REPORT_CSS}</style>
</head>
<body>
<div class="page">
{body_html}
</div>
</body>
</html>"""


def save_report(markdown_text, md_path=REPORT_STATIC, html_path=REPORT_HTML):
    """Write both the Markdown source and the rendered HTML version."""
    Path(md_path).write_text(markdown_text, encoding="utf-8")

    try:
        html_doc = render_html_report(markdown_text)
        Path(html_path).write_text(html_doc, encoding="utf-8")
    except Exception as exc:
        # Never let a rendering problem take down a completed audit —
        # the Markdown file (already written above) is the real result.
        log_error("HTML report rendering failed (Markdown report is still saved)", exc)


# =============================================================================
# STATIC FALLBACK REPORT
# =============================================================================

def generate_static_report(telemetry, reason):
    """
    Generate a minimal fallback report if Claude's final report generation
    fails.
    """

    failure_type = type(reason).__name__
    failure_message = str(reason)
    timestamp = utc_now()

    telemetry_json = json.dumps(
        telemetry,
        indent=2,
        ensure_ascii=False,
    )

    report = (
        "# GRC Compliance Gap Report\n\n"
        "## Assessment Status\n\n"
        "**Status:** Incomplete\n\n"
        "The automated Claude report could not be generated.\n\n"
        f"**Failure type:** `{failure_type}`\n\n"
        f"**Failure message:** `{failure_message}`\n\n"
        f"**Assessment timestamp:** {timestamp}\n\n"
        "## Important Limitation\n\n"
        "This document is a fallback telemetry record and must **not** "
        "be treated as a completed compliance assessment.\n\n"
        "The failure occurred during automated report generation. "
        "The live telemetry below may still be useful for troubleshooting "
        "or manual review.\n\n"
        "## Live Telemetry Collected\n\n"
        "```json\n"
        f"{telemetry_json}\n"
        "```\n\n"
        "## Recommended Action\n\n"
        "Review the error above, correct the underlying issue, "
        "and run the audit again.\n\n"
        "No compliance conclusion should be drawn from this fallback report.\n"
    )

    return report

# =============================================================================
# MAIN PROGRAM
# =============================================================================

def main():
    """Run the complete GRC audit pipeline."""

    print("=" * 60)
    print("GRC AUTOMATED AUDIT PIPELINE")
    print("=" * 60)

    telemetry = {}

    try:
        # ---------------------------------------------------------------------
        # 1. Check required files
        # ---------------------------------------------------------------------

        print("\n[1/7] Checking required files...")

        ensure_file_exists(POLICY_FILE)
        ensure_file_exists(CONTROLS_FILE)

        print("[OK] Required files found.")

        # ---------------------------------------------------------------------
        # 2. Check environment variables
        # ---------------------------------------------------------------------

        print("\n[2/7] Checking credentials...")

        check_sources()
        validate_credentials()

        # ---------------------------------------------------------------------
        # 3. Load policy
        # ---------------------------------------------------------------------

        print("\n[3/7] Loading security policy...")

        policy_text = load_policy()

        print(
            f"[OK] Loaded {POLICY_FILE} "
            f"({len(policy_text):,} characters)."
        )

        # ---------------------------------------------------------------------
        # 4. Load control baseline
        # ---------------------------------------------------------------------

        print("\n[4/7] Loading GRC control baseline...")

        controls = load_controls()

        print("[OK] Control baseline loaded.")

        # ---------------------------------------------------------------------
        # 5. Refresh control baseline with Claude
        # ---------------------------------------------------------------------

        print("\n[5/7] Refreshing GRC control baseline...")

        controls = refresh_control_file(
            policy_text,
            controls,
        )

        print("[OK] Control baseline refreshed.")

        # ---------------------------------------------------------------------
        # 6. Collect live telemetry
        # ---------------------------------------------------------------------

        print("\n[6/7] Collecting live telemetry...")

        telemetry = collect_all_telemetry()

        print("[OK] Live telemetry collected.")

        # ---------------------------------------------------------------------
        # 7. Run audit
        # ---------------------------------------------------------------------

        print("\n[7/7] Running GRC analysis...")

        print("\n--- Phase A: Policy Alignment ---")

        policy_review = run_policy_alignment(
            policy_text,
            controls,
        )

        print("[OK] Phase A complete.")

        print("\n--- Phase B: Live Environment Review ---")

        live_review = run_live_environment_review(
            policy_text,
            controls,
            telemetry,
        )

        print("[OK] Phase B complete.")

        # ---------------------------------------------------------------------
        # Generate final report
        # ---------------------------------------------------------------------

        print("\n--- Generating Final Report ---")

        report = generate_audit_report(
            policy_text,
            controls,
            telemetry,
            policy_review,
            live_review,
        )

        # ---------------------------------------------------------------------
        # Save report (Markdown + rendered HTML)
        # ---------------------------------------------------------------------

        save_report(report)

        print("\n" + "=" * 60)
        print("AUDIT COMPLETE")
        print("=" * 60)
        print(f"Reports saved to:")
        print(f"  {Path(REPORT_STATIC).resolve()}")
        print(f"  {Path(REPORT_HTML).resolve()}")
        print("=" * 60)

        return 0

    except Exception as exc:

        log_error(
            "GRC audit pipeline failed",
            exc,
        )

        print("\n" + "=" * 60)
        print("AUDIT FAILED")
        print("=" * 60)

        # -------------------------------------------------------------
        # Attempt to create a fallback report
        # -------------------------------------------------------------

        try:

            fallback_report = generate_static_report(
                telemetry,
                exc,
            )

            save_report(fallback_report)

            print(
                f"\nIncomplete fallback reports saved to:"
            )

            print(
                f"  {Path(REPORT_STATIC).resolve()}"
            )

            print(
                f"  {Path(REPORT_HTML).resolve()}"
            )

        except Exception as fallback_exc:

            log_error(
                "Could not create fallback report",
                fallback_exc,
            )

        return 1


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    sys.exit(main())

