"""Разбор alerts.json Wazuh и сводный Markdown-отчёт: правила, MITRE, агенты, источники."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Summary:
    """Агрегаты по набору алертов."""

    total: int = 0
    bad_lines: int = 0
    first: datetime | None = None
    last: datetime | None = None
    by_rule: Counter = field(default_factory=Counter)
    by_level: Counter = field(default_factory=Counter)
    by_agent: Counter = field(default_factory=Counter)
    by_technique: Counter = field(default_factory=Counter)
    by_tactic: Counter = field(default_factory=Counter)
    by_srcip: Counter = field(default_factory=Counter)


def parse_ts(value: str) -> datetime:
    """Разобрать время Wazuh вида 2026-10-06T10:00:00.123+0300."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")


def read_alerts(lines: Iterable[str], summary: Summary) -> Iterator[dict]:
    """Читать алерты построчно; битые строки считаются в summary.bad_lines."""
    for line in lines:
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            summary.bad_lines += 1


def summarize(lines: Iterable[str], min_level: int = 0) -> Summary:
    """Посчитать сводку по алертам с уровнем не ниже min_level."""
    s = Summary()
    for alert in read_alerts(lines, s):
        rule = alert.get("rule", {})
        level = int(rule.get("level", 0))
        if level < min_level:
            continue
        s.total += 1
        if ts_raw := alert.get("timestamp"):
            ts = parse_ts(ts_raw)
            s.first = ts if s.first is None else min(s.first, ts)
            s.last = ts if s.last is None else max(s.last, ts)
        s.by_rule[(rule.get("id", "?"), rule.get("description", ""))] += 1
        s.by_level[level_bucket(level)] += 1
        s.by_agent[alert.get("agent", {}).get("name", "?")] += 1
        mitre = rule.get("mitre", {})
        for tid, name in zip(mitre.get("id", []), mitre.get("technique", []), strict=False):
            s.by_technique[f"{tid} {name}"] += 1
        for tactic in mitre.get("tactic", []):
            s.by_tactic[tactic] += 1
        data = alert.get("data", {})
        if src := data.get("srcip") or data.get("src_ip"):
            s.by_srcip[src] += 1
    return s


def level_bucket(level: int) -> str:
    """Отнести уровень Wazuh (0-15) к категории критичности."""
    if level >= 12:
        return "critical (12-15)"
    if level >= 8:
        return "high (8-11)"
    if level >= 4:
        return "medium (4-7)"
    return "low (0-3)"


def _table(title: str, header: tuple[str, str], rows: list[tuple[str, int]]) -> list[str]:
    out = [f"## {title}", "", f"| {header[0]} | {header[1]} |", "|---|---:|"]
    out += [f"| {k} | {v} |" for k, v in rows] or ["| — | 0 |"]
    return out + [""]


def render_markdown(s: Summary, top: int = 10) -> str:
    """Собрать Markdown-отчёт по сводке."""
    period = f"{s.first:%Y-%m-%d %H:%M} — {s.last:%Y-%m-%d %H:%M}" if s.first else "—"
    lines = [
        "# Отчёт по алертам Wazuh",
        "",
        f"- Алертов: **{s.total}**",
        f"- Период: {period}",
        f"- Нераспознанных строк: {s.bad_lines}",
        "",
    ]
    rules = [(f"{rid} — {desc}", n) for (rid, desc), n in s.by_rule.most_common(top)]
    lines += _table("Топ правил", ("Правило", "Срабатываний"), rules)
    lines += _table("Критичность", ("Уровень", "Алертов"), sorted(s.by_level.items()))
    lines += _table("Тактики MITRE ATT&CK", ("Тактика", "Алертов"), s.by_tactic.most_common())
    lines += _table("Техники MITRE ATT&CK", ("Техника", "Алертов"),
                    s.by_technique.most_common(top))
    lines += _table("Агенты", ("Агент", "Алертов"), s.by_agent.most_common(top))
    lines += _table("Топ IP-источников", ("IP", "Алертов"), s.by_srcip.most_common(top))
    return "\n".join(lines)
