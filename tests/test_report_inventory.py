import io
import json

from soclab.alerts_report import level_bucket, render_markdown, summarize
from soclab.inventory import fetch_agents, normalize, status_summary, write_csv


def alert(rule_id: str, level: int, agent: str = "win10", srcip: str | None = None,
          mitre: tuple[str, str, str] | None = None, ts: str = "2026-10-06T10:00:00.000+0300"):
    rule = {"id": rule_id, "level": level, "description": f"rule {rule_id}"}
    if mitre:
        rule["mitre"] = {"id": [mitre[0]], "technique": [mitre[1]], "tactic": [mitre[2]]}
    a = {"timestamp": ts, "rule": rule, "agent": {"name": agent}, "data": {}}
    if srcip:
        a["data"]["srcip"] = srcip
    return json.dumps(a)


def test_summarize_counts():
    lines = [
        alert("100100", 10, "ubuntu", "1.2.3.4", ("T1110.001", "Password Guessing",
                                                  "Credential Access")),
        alert("100100", 10, "ubuntu", "1.2.3.4", ("T1110.001", "Password Guessing",
                                                  "Credential Access"),
              ts="2026-10-06T11:30:00.000+0300"),
        alert("100102", 14, mitre=("T1003.001", "LSASS Memory", "Credential Access")),
        "not json",
        "",
    ]
    s = summarize(lines)
    assert s.total == 3 and s.bad_lines == 1
    assert s.by_agent == {"ubuntu": 2, "win10": 1}
    assert s.by_tactic["Credential Access"] == 3
    assert s.by_srcip["1.2.3.4"] == 2
    assert s.first.hour == 10 and s.last.hour == 11


def test_min_level_filter():
    assert summarize([alert("1", 3), alert("2", 12)], min_level=8).total == 1


def test_level_buckets():
    assert [level_bucket(x) for x in (0, 5, 9, 15)] == [
        "low (0-3)", "medium (4-7)", "high (8-11)", "critical (12-15)"]


def test_render_markdown_contains_sections():
    md = render_markdown(summarize([alert("100106", 10, mitre=("T1046", "Network Service "
                                                               "Discovery", "Discovery"))]))
    assert "# Отчёт по алертам Wazuh" in md and "T1046 Network Service Discovery" in md


def test_render_empty():
    assert "Алертов: **0**" in render_markdown(summarize([]))


class FakeApi:
    """Подмена Wazuh API: две страницы агентов."""

    def __init__(self):
        self.agents = [
            {"id": "000", "name": "manager", "ip": "127.0.0.1", "status": "active",
             "os": {"name": "Ubuntu", "version": "22.04"}, "version": "Wazuh v4.14.0"},
            {"id": "001", "name": "win10", "ip": "192.168.56.20", "status": "active",
             "os": {"name": "Microsoft Windows 10 Pro", "version": "10.0.19045"}},
            {"id": "002", "name": "kali", "status": "never_connected"},
        ]
        self.calls = []

    def get_json(self, path: str) -> dict:
        self.calls.append(path)
        offset = int(path.split("offset=")[1])
        return {"data": {"affected_items": self.agents[offset:offset + 2],
                         "total_affected_items": len(self.agents)}}


def test_fetch_agents_paginates():
    api = FakeApi()
    agents = fetch_agents(api, page_size=2)
    assert [a["id"] for a in agents] == ["000", "001", "002"]
    assert len(api.calls) == 2
    assert status_summary(agents) == {"active": 2, "never_connected": 1}


def test_normalize_missing_fields():
    a = normalize({"id": "003"})
    assert a["os"] == "—" and a["status"] == "unknown"


def test_write_csv():
    buf = io.StringIO()
    write_csv([normalize(FakeApi().agents[1])], buf)
    out = buf.getvalue().splitlines()
    assert out[0].startswith("id,name,ip,status,os")
    assert "Microsoft Windows 10 Pro 10.0.19045" in out[1]
