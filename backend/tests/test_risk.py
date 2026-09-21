from app.scanner.risk import assess_port_risk


def test_telnet_is_high_risk():
    risk = assess_port_risk(23, "telnet")
    assert risk.level == "high"
    assert "текстом" in risk.reason


def test_matches_by_port_even_without_service_name():
    risk = assess_port_risk(23, None)
    assert risk is not None
    assert risk.level == "high"


def test_matches_by_service_keyword_on_nonstandard_port():
    """nmap может определить сервис по баннеру даже на нестандартном порту."""
    risk = assess_port_risk(12345, "vnc")
    assert risk is not None
    assert risk.level == "high"


def test_rdp_is_medium_risk():
    risk = assess_port_risk(3389, "ms-wbt-server")
    assert risk.level == "medium"


def test_https_has_no_rule():
    assert assess_port_risk(443, "https") is None


def test_unknown_port_has_no_rule():
    assert assess_port_risk(54321, "unknown") is None


def test_case_insensitive_service_match():
    risk = assess_port_risk(9999, "TELNET")
    assert risk is not None
    assert risk.level == "high"
