from datetime import datetime, timedelta

from soclab.portscan import Packet, PortScanDetector, detect, parse_line

UFW = (
    "2026-10-06T10:00:{sec:02d}.123456+03:00 ubuntu kernel: [UFW BLOCK] IN=enp0s3 OUT= "
    "MAC=08:00 SRC={src} DST={dst} LEN=44 TOS=0x00 TTL=40 ID=1 PROTO=TCP SPT=40000 "
    "DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0"
)
T0 = datetime(2026, 10, 6, 10, 0, 0)


def pkt(sec: int, dst: str = "10.0.0.5", port: int = 22, src: str = "192.168.56.10") -> Packet:
    return Packet(T0 + timedelta(seconds=sec), src, dst, "TCP", port)


def test_parse_iso_ufw_line():
    p = parse_line(UFW.format(sec=1, src="1.2.3.4", dst="10.0.0.5", port=443))
    assert (p.src, p.dst, p.proto, p.dport) == ("1.2.3.4", "10.0.0.5", "TCP", 443)
    assert p.ts == datetime(2026, 10, 6, 10, 0, 1)


def test_parse_syslog_line_with_year():
    line = ("Oct  6 10:00:01 ubuntu kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=10.0.0.5 "
            "PROTO=UDP SPT=5353 DPT=53")
    p = parse_line(line, year=2026)
    assert p.ts == datetime(2026, 10, 6, 10, 0, 1) and p.proto == "UDP"


def test_parse_non_firewall_line():
    assert parse_line("Oct  6 10:00:01 ubuntu sshd[1]: Accepted password for bob") is None
    assert parse_line("") is None


def test_vertical_scan_detected_once():
    d = PortScanDetector(port_threshold=15)
    alerts = [a for port in range(1, 101) for a in d.feed(pkt(0, port=port))]
    assert len(alerts) == 1
    a = alerts[0]
    assert (a["scan_type"], a["dst_ip"], a["ports_count"], a["mitre"]) == (
        "vertical", "10.0.0.5", 15, "T1046")


def test_below_threshold_is_quiet():
    d = PortScanDetector(port_threshold=15)
    assert not [a for port in range(1, 15) for a in d.feed(pkt(0, port=port))]


def test_slow_scan_outside_window_is_quiet():
    # Один порт раз в 10 секунд: в 60-секундное окно попадает максимум 7 портов
    d = PortScanDetector(window=timedelta(seconds=60), port_threshold=15)
    assert not [a for i in range(50) for a in d.feed(pkt(i * 10, port=i + 1))]


def test_horizontal_scan_detected():
    d = PortScanDetector(host_threshold=10)
    alerts = [a for i in range(20) for a in d.feed(pkt(0, dst=f"10.0.0.{i}", port=445))]
    assert [a["scan_type"] for a in alerts] == ["horizontal"]
    assert alerts[0]["hosts_count"] == 10 and alerts[0]["sample_ports"] == [445]


def test_realert_after_window():
    d = PortScanDetector(window=timedelta(seconds=60), port_threshold=3)
    first = [a for p in range(3) for a in d.feed(pkt(0, port=p))]
    second = [a for p in range(3) for a in d.feed(pkt(200, port=p))]
    assert len(first) == 1 and len(second) == 1


def test_detect_from_lines_ignores_junk():
    lines = ["garbage"] + [
        UFW.format(sec=i % 60, src="5.5.5.5", dst="10.0.0.9", port=1000 + i) for i in range(30)
    ]
    alerts = list(detect(lines))
    assert len(alerts) == 1 and alerts[0]["src_ip"] == "5.5.5.5"
