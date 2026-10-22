from scanner.checks import cookies


def ids(findings):
    return {f.check_id for f in findings}


def test_safe_cookie_has_no_findings(make_response):
    resp = make_response([("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/")])
    assert cookies.check(resp) == []


def test_bare_session_cookie_flags_three_issues(make_response):
    found = cookies.check(make_response([("Set-Cookie", "PHPSESSID=abc123; path=/")]))
    assert ids(found) == {"cookies.no-secure", "cookies.no-httponly", "cookies.no-samesite"}
    secure = next(f for f in found if f.check_id == "cookies.no-secure")
    assert secure.severity.label == "medium"  # session-like name


def test_other_cookie_is_lower_severity(make_response):
    found = cookies.check(make_response([("Set-Cookie", "theme=dark; SameSite=Lax; Secure")]))
    assert [f.severity.label for f in found] == ["low"]


def test_secure_not_required_on_plain_http(make_response):
    resp = make_response([("Set-Cookie", "sid=a; HttpOnly; SameSite=Lax")], scheme="http")
    assert cookies.check(resp) == []


def test_samesite_none_without_secure(make_response):
    resp = make_response([("Set-Cookie", "sid=a; HttpOnly; SameSite=None")], scheme="http")
    assert ids(cookies.check(resp)) == {"cookies.samesite-none-insecure"}


def test_every_set_cookie_header_is_checked(make_response):
    resp = make_response([("Set-Cookie", "a=1; HttpOnly; Secure; SameSite=Lax"),
                          ("Set-Cookie", "b=2")])
    assert {f.title for f in cookies.check(resp)} >= {"Cookie 'b' missing HttpOnly flag"}


def test_cookie_values_never_appear_in_findings(make_response):
    resp = make_response([("Set-Cookie", "session=SUPER-SECRET-VALUE; path=/")])
    for finding in cookies.check(resp):
        text = " ".join([finding.title, finding.description, finding.recommendation, finding.evidence])
        assert "SUPER-SECRET-VALUE" not in text


def test_junk_set_cookie_is_ignored(make_response):
    assert cookies.check(make_response([("Set-Cookie", "=novalue")])) == []
