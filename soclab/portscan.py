"""Детектор сканирования портов по логам iptables/UFW (вертикальный и горизонтальный скан)."""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

# Поля пакета из строки ядра: SRC=... DST=... PROTO=TCP SPT=... DPT=...
_PKT_RE = re.compile(
    r"SRC=(?P<src>[\d.]+) DST=(?P<dst>[\d.]+).*?PROTO=(?P<proto>TCP|UDP).*?DPT=(?P<dpt>\d+)"
)
# 2026-10-06T10:00:01.123456+03:00 host kernel: ...
_ISO_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
# Oct  6 10:00:01 host kernel: ...
_SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})")


@dataclass(frozen=True)
class Packet:
    """Одна попытка соединения из лога файрвола."""

    ts: datetime
    src: str
    dst: str
    proto: str
    dport: int


def parse_line(line: str, year: int | None = None) -> Packet | None:
    """Разобрать строку лога iptables/UFW; None, если это не пакет файрвола."""
    m = _PKT_RE.search(line)
    if not m:
        return None
    if ts_m := _ISO_TS_RE.match(line):
        ts = datetime.fromisoformat(ts_m.group(1))
    elif ts_m := _SYSLOG_TS_RE.match(line):
        # В syslog нет года — подставляем переданный или текущий
        stamp = f"{year or datetime.now().year} {' '.join(ts_m.group(1).split())}"
        ts = datetime.strptime(stamp, "%Y %b %d %H:%M:%S")
    else:
        return None
    return Packet(ts, m["src"], m["dst"], m["proto"], int(m["dpt"]))


class PortScanDetector:
    """Скользящее окно по источнику: много портов одного хоста или один порт многих хостов."""

    def __init__(
        self,
        window: timedelta = timedelta(seconds=60),
        port_threshold: int = 15,
        host_threshold: int = 10,
    ) -> None:
        self.window = window
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self._seen: dict[str, deque[Packet]] = defaultdict(deque)
        # Последний алерт по ключу (src, тип, цель) — чтобы не спамить на каждый пакет
        self._last_alert: dict[tuple[str, str, str], datetime] = {}

    def _should_alert(self, key: tuple[str, str, str], now: datetime) -> bool:
        last = self._last_alert.get(key)
        if last is not None and now - last <= self.window:
            return False
        self._last_alert[key] = now
        return True

    def feed(self, pkt: Packet) -> list[dict]:
        """Учесть пакет и вернуть алерты (словари для JSON)."""
        q = self._seen[pkt.src]
        q.append(pkt)
        while q and pkt.ts - q[0].ts > self.window:
            q.popleft()

        alerts = []
        ports = {p.dport for p in q if p.dst == pkt.dst}
        if len(ports) >= self.port_threshold and self._should_alert(
            (pkt.src, "vertical", pkt.dst), pkt.ts
        ):
            alerts.append(self._alert("vertical", pkt, q, ports=ports, hosts={pkt.dst}))

        hosts = {p.dst for p in q if p.dport == pkt.dport}
        if len(hosts) >= self.host_threshold and self._should_alert(
            (pkt.src, "horizontal", str(pkt.dport)), pkt.ts
        ):
            alerts.append(self._alert("horizontal", pkt, q, ports={pkt.dport}, hosts=hosts))
        return alerts

    def _alert(
        self, scan_type: str, pkt: Packet, q: deque[Packet], ports: set[int], hosts: set[str]
    ) -> dict:
        return {
            "detector": "portscan",
            "scan_type": scan_type,
            "src_ip": pkt.src,
            "dst_ip": pkt.dst if scan_type == "vertical" else None,
            "ports_count": len(ports),
            "hosts_count": len(hosts),
            "sample_ports": sorted(ports)[:20],
            "first_seen": q[0].ts.isoformat(),
            "last_seen": pkt.ts.isoformat(),
            "mitre": "T1046",
        }


def detect(lines: Iterable[str], detector: PortScanDetector | None = None,
           year: int | None = None) -> Iterator[dict]:
    """Прогнать строки лога через детектор и выдать алерты."""
    detector = detector or PortScanDetector()
    for line in lines:
        pkt = parse_line(line, year)
        if pkt is not None:
            yield from detector.feed(pkt)


def follow(path: Path, poll: float = 0.5) -> Iterator[str]:
    """Читать новые строки файла как tail -f."""
    with path.open(encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(poll)


def to_json_line(alert: dict) -> str:
    """Сериализовать алерт в одну JSON-строку (формат localfile json для Wazuh)."""
    return json.dumps(alert, ensure_ascii=False)
