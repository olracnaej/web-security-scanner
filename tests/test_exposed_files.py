import pytest

from scanner import context
from scanner.checks import exposed_files

HTML = b"<html><body>Welcome</body></html>"


def ids(findings):
    return {f.check_id for f in findings}


def site(extra=None, home=HTML):
    routes = {"/": (200, [], home)}
    routes.update(extra or {})
    return routes


def test_clean_site_has_no_findings(serve, make_ctx):
    assert exposed_files.check(make_ctx(serve(site()))) == []


def test_exposed_git_folder(serve, make_ctx):
    base = serve(site({"/.git/HEAD": (200, [], b"ref: refs/heads/main\n")}))
    found = exposed_files.check(make_ctx(base))
    assert ids(found) == {"exposed.git"}
    assert found[0].severity.label == "high"


def test_git_head_and_config_are_one_finding(serve, make_ctx):
    base = serve(site({
        "/.git/HEAD": (200, [], b"ref: refs/heads/main\n"),
        "/.git/config": (200, [], b"[core]\n\trepositoryformatversion = 0\n"),
    }))
    assert [f.check_id for f in exposed_files.check(make_ctx(base))] == ["exposed.git"]


def test_env_file_found_but_secret_never_printed(serve, make_ctx):
    base = serve(site({"/.env": (200, [], b"APP_KEY=base64:s3cr3tvalue\nDB_PASSWORD=hunter2\n")}))
    found = exposed_files.check(make_ctx(base))
    assert ids(found) == {"exposed.env"}
    text = " ".join(f"{f.title} {f.description} {f.recommendation} {f.evidence}" for f in found)
    assert "hunter2" not in text and "s3cr3tvalue" not in text


def test_env_path_returning_html_is_not_a_finding(serve, make_ctx):
    base = serve(site({"/.env": (200, [], b"<html>\nlang=en\n</html>")}))
    assert exposed_files.check(make_ctx(base)) == []


def test_soft_404_site_causes_no_false_alarms(serve, make_ctx):
    # Every unknown path answers 200 with the same page, like many SPAs.
    base = serve({"*": (200, [], b"ref: this page says ref: but it is the soft 404"),
                  "/": (200, [], HTML)})
    assert exposed_files.check(make_ctx(base)) == []


def test_zip_needs_real_zip_bytes(serve, make_ctx):
    fake = serve(site({"/backup.zip": (200, [], b"<html>not a zip</html>")}))
    assert exposed_files.check(make_ctx(fake)) == []
    real = serve(site({"/backup.zip": (200, [], b"PK\x03\x04rest-of-zip")}))
    assert ids(exposed_files.check(make_ctx(real))) == {"exposed.backup-zip"}


def test_sql_dump_and_phpinfo(serve, make_ctx):
    base = serve(site({
        "/dump.sql": (200, [], b"-- MySQL dump 10.13\nCREATE TABLE users (id int);"),
        "/phpinfo.php": (200, [], b"<title>phpinfo()</title> PHP Version 8.2"),
    }))
    assert ids(exposed_files.check(make_ctx(base))) == {"exposed.sql-dump", "exposed.phpinfo"}


def test_directory_listing_detected(serve, make_ctx):
    base = serve(site(home=b"<html><head><title>Index of /</title></head></html>"))
    assert ids(exposed_files.check(make_ctx(base))) == {"exposed.directory-listing"}


def test_python_http_server_style_listing_detected(serve, make_ctx):
    base = serve(site(home=b"<title>Directory listing for /</title>"))
    assert "exposed.directory-listing" in ids(exposed_files.check(make_ctx(base)))


def test_probe_cannot_leave_the_authorized_host(serve, make_ctx):
    ctx = make_ctx(serve(site()))
    with pytest.raises(ValueError):
        ctx.probe("//evil.example/x")
    with pytest.raises(ValueError):
        ctx.probe("http://169.254.169.254/")


def test_probe_cap_is_enforced(serve, make_ctx, monkeypatch):
    monkeypatch.setattr(context, "MAX_PROBES", 3)
    ctx = make_ctx(serve(site()))
    results = [ctx.probe("/") for _ in range(5)]
    assert [r is not None for r in results] == [True, True, True, False, False]
