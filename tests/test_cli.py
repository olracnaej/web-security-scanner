from scanner.cli import EXIT_FETCH_ERROR, EXIT_FINDINGS, EXIT_OK, EXIT_REFUSED, main

BARE = {"/": (200, [], b"<html></html>")}


def test_scan_prints_report(serve, capsys):
    assert main(["scan", serve(BARE)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Findings:" in out and "Missing Content-Security-Policy" in out
    assert "Fix:" in out


def test_fail_on_returns_exit_code_1(serve):
    assert main(["scan", serve(BARE), "--fail-on", "medium"]) == EXIT_FINDINGS


def test_fail_on_high_passes_when_nothing_that_bad(serve):
    assert main(["scan", serve(BARE), "--fail-on", "high"]) == EXIT_OK


def test_refused_target_exit_code(capsys):
    assert main(["scan", "http://169.254.169.254/"]) == EXIT_REFUSED
    assert "Refused" in capsys.readouterr().err


def test_public_site_refused_without_permission(capsys, monkeypatch):
    monkeypatch.setattr(
        "scanner.safety.socket.getaddrinfo",
        lambda host, port, type=0, **_: [(2, type, 6, "", ("93.184.216.34", port))],
    )
    assert main(["scan", "https://example.com"]) == EXIT_REFUSED


def test_unreachable_site_exit_code(capsys):
    assert main(["scan", "http://127.0.0.1:1/"]) == EXIT_FETCH_ERROR
    assert "Error:" in capsys.readouterr().err
