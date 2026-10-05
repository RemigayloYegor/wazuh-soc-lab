import json

from soclab.cli import main

UFW = ("2026-10-06T10:00:{sec:02d}+03:00 ubuntu kernel: [UFW BLOCK] SRC=192.168.56.10 "
       "DST=192.168.56.30 PROTO=TCP SPT=40000 DPT={port}")


def test_portscan_writes_json(tmp_path, capsys):
    log = tmp_path / "ufw.log"
    log.write_text("\n".join(UFW.format(sec=i % 60, port=i) for i in range(1, 40)),
                   encoding="utf-8")
    out = tmp_path / "portscan.json"
    assert main(["portscan", str(log), "-o", str(out)]) == 0
    alerts = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    assert len(alerts) == 1 and alerts[0]["detector"] == "portscan"
    assert "найдено сканов: 1" in capsys.readouterr().err


def test_portscan_missing_file(tmp_path, capsys):
    assert main(["portscan", str(tmp_path / "nope.log")]) == 1
    assert "не найден" in capsys.readouterr().err


def test_report_to_file(tmp_path):
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps({"timestamp": "2026-10-06T10:00:00.000+0300",
                                  "rule": {"id": "100101", "level": 12, "description": "x"},
                                  "agent": {"name": "win10"}}), encoding="utf-8")
    out = tmp_path / "report.md"
    assert main(["report", str(alerts), "-o", str(out)]) == 0
    assert "100101" in out.read_text(encoding="utf-8")


def test_report_missing_file(tmp_path, capsys):
    assert main(["report", str(tmp_path / "x.json")]) == 1
    assert "не найден" in capsys.readouterr().err


def test_agents_connection_error(monkeypatch, capsys):
    monkeypatch.setenv("WAZUH_API_PASSWORD", "x")
    # Порт 9 на localhost закрыт — ожидаем понятную ошибку, а не трейсбек
    assert main(["agents", "--url", "https://127.0.0.1:9", "-k"]) == 1
    assert "ошибка подключения" in capsys.readouterr().err
