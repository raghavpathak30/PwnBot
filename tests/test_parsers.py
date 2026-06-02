import json

from pwnbot.parsers import parse_nmap_xml, parse_ffuf_json
from pwnbot.state import TargetState


def test_parse_nmap_xml():
    # Minimal nmap XML sample with one open port
    sample = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="8.2p1" />
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" />
      </port>
    </ports>
  </host>
</nmaprun>
'''

    ts = TargetState()
    summary = parse_nmap_xml(sample, ts)
    assert summary is not None
    assert '22/tcp' in summary
    assert 'ssh' in summary
    # TargetState should be populated with the open port
    assert '22' in ts.ports


def test_parse_ffuf_json():
    sample = {
        "results": [
            {"url": "http://example.com/admin", "status": 200},
            {"url": "http://example.com/login", "status": 403},
        ]
    }

    summary = parse_ffuf_json(json.dumps(sample), None)
    assert summary is not None
    assert '200' in summary
    assert '403' in summary
