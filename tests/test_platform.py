from webcare import platform
from webcare.model import CheckResult
from webcare.targets import Target


def judged(ssl, network, data="synthetic"):
    target = Target(name="t", env="staging", data=data)
    return platform.judge(CheckResult(id="platform", title="t"), ssl, network, target)


def test_enforced_ssl_and_restricted_network_pass():
    result = judged({"currentConfig": {"database": True}},
                    {"entitlement": "allowed", "config": {"dbAllowedCidrs": ["203.0.113.0/24"]}, "status": "applied"})
    assert result.status == "PASS" and "1 address ranges" in result.notes[-1]


def test_ssl_off_is_high_for_real_data():
    result = judged({"currentConfig": {"database": False}}, {"entitlement": "disallowed", "config": {}}, data="real")
    assert [(f.rule, f.severity) for f in result.findings] == [("ssl_not_enforced", "high")]
    assert any("not available on this project's plan" in note for note in result.notes)


def test_answers_in_an_unknown_shape_are_never_read_as_safe():
    result = judged({"something": "else"}, ["not", "a", "dict"])
    assert result.status == "ERROR"
    partly = judged({"currentConfig": {"database": True}}, {"no": "config"})
    assert any("not in a known shape" in note for note in partly.notes)
