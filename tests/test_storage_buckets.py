import json

import pytest

from webcare import health, live, storage_buckets
from webcare.model import CheckResult
from webcare.targets import Target


def bucket(name="files", public=False, policies=1, anon=(), size=True, types=True):
    return {"bucket": name, "public": public, "policies": policies, "anon_commands": list(anon),
            "has_size_limit": size, "has_type_list": types}


def judged(*buckets, unscoped=(), expected=()):
    target = Target(name="t", env="staging", data="synthetic", expected_public_buckets=tuple(expected))
    report = {"format": storage_buckets.FORMAT, "taken_at": "now", "buckets": list(buckets),
              "unscoped_policies": list(unscoped)}
    return storage_buckets.judge(CheckResult(id="storage_buckets", title=storage_buckets.TITLE), report, target)


def found(result):
    return {(f.rule, f.severity, f.location) for f in result.findings}


def test_statements_are_single_selects_that_read_no_object_row():
    for sql in (storage_buckets.PROBE_SQL, storage_buckets.SQL):
        live.assert_single_select(sql)
    assert "storage.objects" not in storage_buckets.SQL  # policies come from pg_policies, by name
    assert "from storage.buckets" in storage_buckets.SQL


def test_private_buckets_with_limits_pass():
    result = judged(bucket(), bucket("archive", policies=0, size=False, types=False))
    assert result.status == "PASS" and "2 buckets examined (0 public)" in result.notes[0]


def test_public_buckets_are_judged_against_the_declared_list():
    assert found(judged(bucket("site", public=True))) == {("storage_bucket_public", "medium", "bucket 'site'")}
    assert judged(bucket("site", public=True), expected=["site"]).status == "PASS"
    assert found(judged(bucket("site"), expected=["site", "gone"])) == {
        ("expected_public_bucket_missing", "low", "bucket 'site'"),
        ("expected_public_bucket_missing", "low", "bucket 'gone'"),
    }


def test_anonymous_access_and_missing_limits_are_reported():
    assert found(judged(bucket(anon=["INSERT", "SELECT"]))) == {("storage_anon_write", "medium", "bucket 'files'")}
    assert found(judged(bucket(anon=["SELECT"]))) == {("storage_anon_read", "low", "bucket 'files'")}
    assert found(judged(bucket(size=False, types=False))) == {("storage_no_upload_limits", "low", "bucket 'files'")}
    assert judged(bucket(size=False, types=True)).status == "PASS"


def test_policies_that_name_no_bucket_are_reported_by_who_they_reach():
    unscoped = [{"policy": "any", "command": "SELECT", "roles": ["public"]},
                {"policy": "mine", "command": "ALL", "roles": ["authenticated"]}]
    assert found(judged(bucket(), unscoped=unscoped)) == {
        ("storage_policy_every_bucket", "medium", "storage.objects policy 'any'"),
        ("storage_policy_every_bucket", "low", "storage.objects policy 'mine'"),
    }


@pytest.mark.parametrize("probe, text", [
    (dict(installed=False), "no storage.buckets table"),
    (dict(installed=True, readable=False, role="r"), "may not read"),
    (dict(installed=True, readable=True, row_security=True, sees_every_row=False, role="r"), "shown no bucket"),
])
def test_a_role_that_cannot_see_the_buckets_is_not_run(probe, text):
    asked = []

    def ask(sql):
        asked.append(sql)
        return [{"probe": dict(probe, format=health.PROBE_FORMAT)}]

    target = Target(name="t", env="staging", data="synthetic")
    result = storage_buckets.run(ask, target, "evidence")
    assert result.status == "NOT_RUN" and text in result.reason and len(asked) == 1


def test_against_a_database(pg):
    import psycopg
    from psycopg.rows import dict_row

    target = Target(name="t", env="local", data="synthetic")
    with psycopg.connect(pg.admin_bad, row_factory=dict_row) as connection:
        result = storage_buckets.run_on_connection(connection, target, "local")
    assert result.status == "FINDINGS", result.reason
    assert ("storage_policy_every_bucket", "low", "storage.objects policy 'own files any bucket'") in found(result)
    assert "avatars insert" not in json.dumps(result.to_dict())  # scoped to its bucket, so not reported

    connection = live.connect(pg.auditor_bad)
    try:
        result = storage_buckets.run_on_connection(connection, target, "local")
    finally:
        connection.close()
    assert result.status == "NOT_RUN"
