"""Sign-in settings of the project (Supabase Auth), judged from a short allowlist.

One GET of the project's Auth configuration through the Management API, and
only when the operator asks with `--with-auth-config`. The access token needs
the `auth_config_read` permission for it.

That answer also carries secrets: the mail server password, OAuth client
secrets, hook secrets, SMS provider keys. Supabase's reference does not say
whether they come back masked. So the first thing done with the answer is
`keep()`: copy the few named settings below into a new dict and drop the rest
unread. Nothing else in this package ever sees the full answer, and it is
never written anywhere. The secrets do reach this process's memory for that
moment; that is what asking this endpoint costs.
"""

from __future__ import annotations

from .model import ERROR, CheckResult, Finding
from .targets import Target

TITLE = "Sign-in settings (Supabase Auth)"
SOURCE = "auth"
NOT_ASKED = (
    "not asked for; add --with-auth-config to --via-api (the token then also needs "
    "auth_config_read, and the endpoint's answer includes secrets that the tool discards)"
)

# The only fields that survive. None of them is a credential.
KEPT = (
    "disable_signup", "external_anonymous_users_enabled", "mailer_autoconfirm", "sms_autoconfirm",
    "external_email_enabled", "external_phone_enabled",
    "password_min_length", "password_required_characters", "password_hibp_enabled",
    "mfa_totp_verify_enabled", "mfa_phone_verify_enabled", "mfa_web_authn_verify_enabled",
    "jwt_exp", "refresh_token_rotation_enabled", "security_refresh_token_reuse_interval",
    "sessions_timebox", "sessions_inactivity_timeout",
    "security_captcha_enabled", "security_update_password_require_reauthentication",
    "site_url", "uri_allow_list",
)
_SIMPLE = (bool, int, float, str, type(None))


def keep(answer) -> dict:
    """The allowlisted settings, and nothing else, as plain values."""
    if not isinstance(answer, dict):
        return {}
    kept = {name: answer[name] for name in KEPT if name in answer and isinstance(answer[name], _SIMPLE)}
    if isinstance(answer.get("custom_mail_server"), bool):  # already reduced once
        kept["custom_mail_server"] = answer["custom_mail_server"]
    else:
        kept["custom_mail_server"] = bool(answer.get("smtp_host"))  # a yes/no fact, not the host
    return kept


def _number(value) -> int:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def judge(result: CheckResult, settings: dict, target: Target) -> CheckResult:
    if "disable_signup" not in settings and "jwt_exp" not in settings:
        result.status, result.reason = ERROR, "the Auth configuration was not in the documented shape"
        return result
    real = target.data == "real" or target.env == "production"
    place = f"project {target.project_ref}"

    def add(rule: str, severity: str, message: str) -> None:
        result.findings.append(Finding(SOURCE, rule, severity, place, message))

    def known(name: str) -> bool:
        return settings.get(name) is not None

    signup_open = settings.get("disable_signup") is False
    if signup_open and not target.expected_open_signup:
        add(
            "auth_signup_open", "medium",
            "anyone can create an account; every policy written TO authenticated applies to "
            "them. If open sign-up is intended, set expected_open_signup = true on the target.",
        )
    if settings.get("external_anonymous_users_enabled") is True:
        add(
            "auth_anonymous_signins", "medium",
            "anonymous sign-ins are on: a visitor gets a session with the authenticated role "
            "without giving any credential",
        )
    if settings.get("mailer_autoconfirm") is True:
        add(
            "auth_email_not_confirmed", "medium" if signup_open else "low",
            "new accounts are confirmed without proving the e-mail address belongs to them",
        )
    if known("password_min_length"):
        length = _number(settings["password_min_length"])
        if length < 8:
            add("auth_password_short", "medium", f"the minimum password length is {length}")
        elif length < 10:
            add("auth_password_short", "low", f"the minimum password length is {length}")
    if settings.get("password_hibp_enabled") is False:
        add(
            "auth_leaked_password_check_off", "low",
            "passwords are not checked against known leaked passwords (a paid-plan feature)",
        )
    mfa = [name for name in KEPT if name.startswith("mfa_") and known(name)]
    if mfa and not any(settings[name] is True for name in mfa):
        add(
            "auth_mfa_unavailable", "medium" if real else "low",
            "no second factor can be verified, so accounts rest on the password alone",
        )
    if known("jwt_exp"):
        seconds = _number(settings["jwt_exp"])
        if seconds > 86400:
            add("auth_token_long_lived", "medium", f"an access token stays valid for {seconds // 3600} hours")
        elif seconds > 3600:
            add("auth_token_long_lived", "low", f"an access token stays valid for {seconds // 60} minutes")
    if settings.get("refresh_token_rotation_enabled") is False:
        add(
            "auth_refresh_rotation_off", "medium",
            "refresh tokens are not rotated, so a stolen one keeps working unnoticed",
        )
    if (
        real and (known("sessions_timebox") or known("sessions_inactivity_timeout"))
        and not _number(settings.get("sessions_timebox")) and not _number(settings.get("sessions_inactivity_timeout"))
    ):
        add(
            "auth_sessions_never_expire", "low",
            "sessions have no time limit and no inactivity timeout (a paid-plan feature)",
        )
    if signup_open and settings.get("security_captcha_enabled") is False:
        add("auth_no_captcha", "low", "sign-up is open and no CAPTCHA protects it")
    site = str(settings.get("site_url") or "")
    if site.startswith("http://") and not site.startswith(("http://localhost", "http://127.0.0.1")) or (
        real and site.startswith(("http://localhost", "http://127.0.0.1"))
    ):
        add("auth_site_url_insecure", "low", f"the site URL is {site}, which is not an https address of the site")
    redirects = [entry.strip() for entry in str(settings.get("uri_allow_list") or "").split(",") if entry.strip()]
    loose = [entry for entry in redirects if entry in ("*", "**") or entry.startswith(("http://*", "https://*", "*"))]
    if loose:
        add(
            "auth_redirect_wildcard", "medium",
            f"the redirect allow list accepts any host ({', '.join(loose[:3])}); a sign-in "
            "link can then send its token to a site an attacker controls",
        )
    if real and settings.get("custom_mail_server") is False:
        add(
            "auth_builtin_mailer", "low",
            "sign-in e-mail goes through the platform's built-in sender, which is rate "
            "limited and not meant for production",
        )
    result.notes.append(
        f"{len(settings)} settings read from an allowlist; every other field of the answer, "
        "including all secrets, was discarded without being read, stored or shown"
    )
    missing = [name for name in ("disable_signup", "password_min_length", "jwt_exp", "refresh_token_rotation_enabled") if not known(name)]
    if missing:
        result.notes.append("not present in the answer, so not judged: " + ", ".join(missing))
    return result.finish()


def run(target: Target, fetch, evidence: str) -> CheckResult:
    """`fetch` returns the endpoint's decoded answer; it is reduced before anything reads it."""
    result = CheckResult(id="auth_config", title=TITLE, evidence=evidence)
    return judge(result, keep(fetch()), target)
