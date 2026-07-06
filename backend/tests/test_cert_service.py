"""
_classify_probe_exception() backs the MTA-STS/MX probe diagnosis — turning
a raw exception into one of a small set of named kinds (dns/refused/
timeout/tls/other) so the diagnosis layer (mta_sts_hosting._diagnose) can
tell "no subdomain at all" apart from "a host exists but nothing answers
HTTPS" apart from "TLS works but the cert chain isn't trusted".
"""
import socket
import ssl

from app.services.cert_service import _classify_probe_exception, _detect_gateway, _annotate_error


def test_classifies_dns_failure():
    assert _classify_probe_exception(socket.gaierror("Name or service not known")) == "dns"


def test_classifies_connection_refused():
    assert _classify_probe_exception(ConnectionRefusedError()) == "refused"


def test_classifies_timeout():
    assert _classify_probe_exception(TimeoutError()) == "timeout"


def test_classifies_tls_error():
    assert _classify_probe_exception(ssl.SSLError("certificate verify failed")) == "tls"


def test_classifies_unknown_exception_as_other():
    assert _classify_probe_exception(ValueError("something else")) == "other"


# ── Known mail security gateway detection + error annotation ───────────────
# Real-world case from conversation: za-smtp-inbound-1.mimecast.co.za timed
# out on a direct socket connect on BOTH port 25 and port 443 — confirmed
# not a code bug, but Mimecast's infrastructure not responding to an
# unrecognized prober (common deliberate anti-abuse behavior for major
# mail security gateways). The raw "timed out" string told the user
# nothing about this; _annotate_error fills that gap.

def test_detect_gateway_matches_mimecast():
    assert _detect_gateway("za-smtp-inbound-1.mimecast.co.za") == "Mimecast"


def test_detect_gateway_matches_proofpoint_pphosted():
    assert _detect_gateway("mx0a-001234.pphosted.com") == "Proofpoint"


def test_detect_gateway_returns_none_for_unrecognized_host():
    assert _detect_gateway("mx1.example.com") is None


def test_annotate_error_adds_gateway_context_for_timeout():
    msg = _annotate_error("za-smtp-inbound-1.mimecast.co.za", "timeout", "timed out")
    assert "Mimecast" in msg
    assert "anti-abuse" in msg
    assert msg.startswith("timed out")  # original error preserved, not replaced


def test_annotate_error_adds_gateway_context_for_refused():
    msg = _annotate_error("mx0a-001234.pphosted.com", "refused", "Connection refused")
    assert "Proofpoint" in msg
    assert "refused the connection" in msg


def test_annotate_error_leaves_unrecognized_host_unchanged():
    msg = _annotate_error("mx1.example.com", "timeout", "timed out")
    assert msg == "timed out"


def test_annotate_error_does_not_annotate_dns_or_tls_failures():
    """A DNS or TLS-chain failure isn't something a gateway vendor explains
    away — only connectivity-level (timeout/refused) failures get annotated."""
    msg = _annotate_error("za-smtp-inbound-1.mimecast.co.za", "dns", "Name or service not known")
    assert msg == "Name or service not known"
