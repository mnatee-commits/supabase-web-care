import re

from webcare import auth_config
from webcare.model import CheckResult
from webcare.targets import Target

REF = "abcdefghijklmnopqrst"
GOOD = {"disable_signup": True, "external_anonymous_users_enabled": False, "mailer_autoconfirm": False,
        "password_min_length": 12, "password_hibp_enabled": True, "mfa_totp_verify_enabled": True,
        "mfa_phone_verify_enabled": False, "jwt_exp": 3600, "refresh_token_rotation_enabled": True,
        "sessions_timebox": 43200, "sessions_inactivity_timeout": 0, "security_captcha_enabled": False,
        "site_url": "https://app.example.com", "uri_allow_list": "https://app.example.com/**,https://x.example.com",
        "smtp_host": "mail.example.com"}


def judged(data="real", open_signup=False, **changes):
    target = Target(name="t", env="staging", data=data, project_ref=REF, expected_open_signup=open_signup)
    result = CheckResult(id="auth_config", title=auth_config.TITLE)
    return auth_config.judge(result, auth_config.keep({**GOOD, **changes}), target)


def rules(result):
    return {(finding.rule, finding.severity) for finding in result.findings}


def test_the_allowlist_holds_no_field_that_could_be_a_credential():
    for name in auth_config.KEPT:
        assert not re.search(r"secret|pass(?!word_)|_key|token(?!_rotation|_reuse)|private|smtp|client_id", name), name
    answer = {**GOOD, "smtp_pass": "x", "external_github_secret": "y", "hook_send_email_secrets": "z",
              "site_url": {"nested": "object"}, "smtp_admin_email": "someone@example.com"}
    kept = auth_config.keep(answer)
    assert set(kept) <= set(auth_config.KEPT) | {"custom_mail_server"}
    assert "site_url" not in kept and kept["custom_mail_server"] is True
    assert auth_config.keep(kept) == kept and auth_config.keep("nonsense") == {}


def test_careful_settings_pass_and_the_note_says_what_was_discarded():
    result = judged()
    assert result.status == "PASS", [finding.rule for finding in result.findings]
    assert "including all secrets, was discarded" in result.notes[0]


def test_open_sign_up_and_its_companions():
    assert rules(judged(disable_signup=False)) == {("auth_signup_open", "medium"), ("auth_no_captcha", "low")}
    assert rules(judged(disable_signup=False, open_signup=True, security_captcha_enabled=True)) == set()
    assert rules(judged(mailer_autoconfirm=True)) == {("auth_email_not_confirmed", "low")}
    assert ("auth_email_not_confirmed", "medium") in rules(judged(mailer_autoconfirm=True, disable_signup=False))
    assert rules(judged(external_anonymous_users_enabled=True)) == {("auth_anonymous_signins", "medium")}


def test_passwords_tokens_and_second_factors():
    assert rules(judged(password_min_length=6)) == {("auth_password_short", "medium")}
    assert rules(judged(password_min_length=8)) == {("auth_password_short", "low")}
    assert rules(judged(password_hibp_enabled=False)) == {("auth_leaked_password_check_off", "low")}
    assert rules(judged(mfa_totp_verify_enabled=False)) == {("auth_mfa_unavailable", "medium")}
    assert rules(judged(mfa_totp_verify_enabled=False, data="synthetic")) == {("auth_mfa_unavailable", "low")}
    assert rules(judged(jwt_exp=7200)) == {("auth_token_long_lived", "low")}
    assert rules(judged(jwt_exp=604800)) == {("auth_token_long_lived", "medium")}
    assert rules(judged(refresh_token_rotation_enabled=False)) == {("auth_refresh_rotation_off", "medium")}
    assert rules(judged(sessions_timebox=0)) == {("auth_sessions_never_expire", "low")}
    assert rules(judged(sessions_timebox=0, data="synthetic")) == set()


def test_urls_and_mail():
    assert rules(judged(uri_allow_list="https://app.example.com, **")) == {("auth_redirect_wildcard", "medium")}
    assert rules(judged(site_url="http://app.example.com")) == {("auth_site_url_insecure", "low")}
    assert rules(judged(site_url="http://localhost:3000")) == {("auth_site_url_insecure", "low")}
    assert rules(judged(site_url="http://localhost:3000", data="synthetic")) == set()
    assert rules(judged(smtp_host="")) == {("auth_builtin_mailer", "low")}


def test_an_answer_without_the_settings_is_an_error():
    target = Target(name="t", env="staging", data="synthetic", project_ref=REF)
    result = auth_config.judge(CheckResult(id="auth_config", title=auth_config.TITLE), auth_config.keep({"message": "x"}), target)
    assert result.status == "ERROR"
