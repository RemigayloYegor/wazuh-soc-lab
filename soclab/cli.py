"""CLI soclab: portscan / report / agents."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import timedelta
from pathlib import Path
from urllib.error import URLError

from soclab import alerts_report, inventory, portscan


def cmd_portscan(args: argparse.Namespace) -> int:
    src = Path(args.log)
    if not src.is_file():
        print(f"ошибка: файл не найден: {src}", file=sys.stderr)
        return 1
    detector = portscan.PortScanDetector(
        window=timedelta(seconds=args.window),
        port_threshold=args.ports,
        host_threshold=args.hosts,
    )
    if args.follow:
        lines = portscan.follow(src)
    else:
        lines = src.read_text(encoding="utf-8", errors="replace").splitlines()
    out = open(args.output, "a", encoding="utf-8") if args.output else sys.stdout
    count = 0
    try:
        for alert in portscan.detect(lines, detector, year=args.year):
            print(portscan.to_json_line(alert), file=out, flush=True)
            count += 1
    except KeyboardInterrupt:
        pass
    finally:
        if out is not sys.stdout:
            out.close()
    print(f"найдено сканов: {count}", file=sys.stderr)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    src = Path(args.alerts)
    if not src.is_file():
        print(f"ошибка: файл не найден: {src}", file=sys.stderr)
        return 1
    with src.open(encoding="utf-8", errors="replace") as f:
        summary = alerts_report.summarize(f, min_level=args.min_level)
    md = alerts_report.render_markdown(summary, top=args.top)
    if args.output:
        Path(args.output).write_text(md, encoding="utf-8")
        print(f"отчёт сохранён: {args.output} (алертов: {summary.total})")
    else:
        print(md)
    return 0


def cmd_agents(args: argparse.Namespace) -> int:
    password = os.environ.get("WAZUH_API_PASSWORD") or getpass.getpass("Пароль Wazuh API: ")
    try:
        api = inventory.WazuhApi(args.url, args.user, password, verify_tls=not args.insecure)
        agents = inventory.fetch_agents(api)
    except (URLError, OSError, KeyError) as exc:
        print(f"ошибка подключения к Wazuh API: {exc}", file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as f:
            inventory.write_csv(agents, f)
        print(f"агентов: {len(agents)}, CSV: {args.output}")
    else:
        inventory.write_csv(agents, sys.stdout)
    for status, n in sorted(inventory.status_summary(agents).items()):
        print(f"  {status}: {n}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Собрать парсер аргументов."""
    p = argparse.ArgumentParser(prog="soclab", description="Инструменты SOC-лаборатории Wazuh")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("portscan", help="найти сканы портов в логе iptables/UFW")
    ps.add_argument("log", help="например /var/log/ufw.log")
    ps.add_argument("-o", "--output", help="дописывать алерты JSON в файл (его читает Wazuh)")
    ps.add_argument("-f", "--follow", action="store_true", help="следить за файлом как tail -f")
    ps.add_argument("--window", type=int, default=60, help="окно, секунд (60)")
    ps.add_argument("--ports", type=int, default=15, help="порог портов на хост (15)")
    ps.add_argument("--hosts", type=int, default=10, help="порог хостов на порт (10)")
    ps.add_argument("--year", type=int, help="год для syslog-времени без года")
    ps.set_defaults(func=cmd_portscan)

    rp = sub.add_parser("report", help="Markdown-отчёт по alerts.json")
    rp.add_argument("alerts", help="/var/ossec/logs/alerts/alerts.json")
    rp.add_argument("-o", "--output")
    rp.add_argument("--min-level", type=int, default=0)
    rp.add_argument("--top", type=int, default=10)
    rp.set_defaults(func=cmd_report)

    ag = sub.add_parser("agents", help="учёт агентов через Wazuh API")
    ag.add_argument("--url", default="https://localhost:55000")
    ag.add_argument("--user", default="wazuh-wui")
    ag.add_argument("-o", "--output", help="CSV-файл")
    ag.add_argument("-k", "--insecure", action="store_true", help="не проверять TLS (лаба)")
    ag.set_defaults(func=cmd_agents)
    return p


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI."""
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
