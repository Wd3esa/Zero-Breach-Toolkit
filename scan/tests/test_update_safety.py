"""Indicator updates refuse a sudden collapse in a source's count, every list
format drops whole shared services, PowerShell loads only Windows' modules,
and update requests carry a generic user agent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import feeds
from zbtriage.modules import host


def _src(fmt="domains-txt"):
    return {"id": "t", "name": "T", "url": "https://raw.githubusercontent.com/x/y/main/t.txt",
            "format": fmt, "cite": "c", "category": "mercenary", "family": "f"}


def _body(n):
    return "".join("bad{}.example\n".format(i) for i in range(n)).encode()


def test_update_refuses_a_collapsed_list_and_keeps_the_previous(tmp_path):
    cache = str(tmp_path)
    first = feeds.update(cache, [_src()], fetch=lambda u: _body(100))
    assert first["failed"] == 0
    second = feeds.update(cache, [_src()], fetch=lambda u: _body(10))
    entry = second["sources"][0]
    assert entry["status"] == "failed" and entry["kept_previous"]
    assert "fell from 100 to 10" in entry["error"]
    assert feeds.read_manifest(cache)["t"]["indicators"] == 100


def test_update_accepts_ordinary_changes(tmp_path):
    cache = str(tmp_path)
    feeds.update(cache, [_src()], fetch=lambda u: _body(100))
    assert feeds.update(cache, [_src()], fetch=lambda u: _body(70))["failed"] == 0


def test_every_list_format_drops_shared_services(tmp_path):
    lists = {
        "domains-txt": "github.com\nt.me\nreal-bad.example\n",
        "csv-domain-ip": "domain_name,ip_address\ngithub.com,\nt.me,\nreal-bad.example,\n",
        "misp-csv": "type,value\ndomain,github.com\nurl,https://t.me/x\ndomain,real-bad.example\n",
    }
    for fmt, text in lists.items():
        path = tmp_path / (fmt + ".txt")
        path.write_text(text)
        values = {i.value for i in feeds.load_list(str(path), fmt, "s", "f").indicators}
        assert values == {"real-bad.example"}, (fmt, values)


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell module path is Windows-only")
def test_powershell_loads_only_windows_modules():
    env = host.powershell_env()
    assert env["PSModulePath"].endswith(os.path.join("System32", "WindowsPowerShell", "v1.0", "Modules"))
    assert os.pathsep not in env["PSModulePath"]


def test_update_request_uses_a_generic_user_agent(monkeypatch):
    seen = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"x.example\n"

    class _Opener:
        def open(self, req, timeout):
            seen["ua"] = req.get_header("User-agent")
            return _Resp()

    monkeypatch.setattr(feeds.urllib.request, "build_opener", lambda *a: _Opener())
    feeds._fetch(feeds.SOURCES[0]["url"])
    assert seen["ua"] == "Mozilla/5.0"
