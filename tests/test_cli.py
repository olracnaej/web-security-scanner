from scanner.cli import EXIT_OK, EXIT_REFUSED, main


def test_scan_localhost_ok(capsys):
    assert main(["scan", "http://127.0.0.1:8001"]) == EXIT_OK
    assert "Authorized: 127.0.0.1:8001 (loopback)" in capsys.readouterr().out


def test_scan_public_site_refused_without_permission(capsys, monkeypatch):
    monkeypatch.setattr(
        "scanner.safety.socket.getaddrinfo",
        lambda host, port, type=0, **_: [(2, type, 6, "", ("93.184.216.34", port))],
    )
    assert main(["scan", "https://example.com"]) == EXIT_REFUSED
    assert "Refused" in capsys.readouterr().err


def test_scan_public_site_with_allow_host(monkeypatch):
    monkeypatch.setattr(
        "scanner.safety.socket.getaddrinfo",
        lambda host, port, type=0, **_: [(2, type, 6, "", ("93.184.216.34", port))],
    )
    assert main(["scan", "https://example.com", "--allow-host", "example.com"]) == EXIT_OK
