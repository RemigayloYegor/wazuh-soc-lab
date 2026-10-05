"""Учёт узлов: список агентов из Wazuh API со статусом и ОС, экспорт в CSV."""

from __future__ import annotations

import base64
import csv
import json
import ssl
import urllib.request
from collections import Counter
from typing import IO, Protocol

FIELDS = ("id", "name", "ip", "status", "os", "version", "last_keepalive")


class ApiClient(Protocol):
    """Минимальный интерфейс клиента — нужен, чтобы подменять его в тестах."""

    def get_json(self, path: str) -> dict: ...


class WazuhApi:
    """Клиент Wazuh API (порт 55000) на стандартной библиотеке."""

    def __init__(self, url: str, user: str, password: str, verify_tls: bool = True) -> None:
        self.url = url.rstrip("/")
        # В лаборатории у менеджера самоподписанный сертификат
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.token = self._authenticate(user, password)

    def _request(self, path: str, method: str, headers: dict) -> dict:
        req = urllib.request.Request(self.url + path, method=method, headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as resp:
            return json.load(resp)

    def _authenticate(self, user: str, password: str) -> str:
        basic = base64.b64encode(f"{user}:{password}".encode()).decode()
        data = self._request("/security/user/authenticate", "POST",
                             {"Authorization": f"Basic {basic}"})
        return data["data"]["token"]

    def get_json(self, path: str) -> dict:
        """GET-запрос к API с JWT-токеном."""
        return self._request(path, "GET", {"Authorization": f"Bearer {self.token}"})


def fetch_agents(client: ApiClient, page_size: int = 500) -> list[dict]:
    """Получить всех агентов постранично и привести к плоскому виду."""
    agents: list[dict] = []
    offset = 0
    while True:
        data = client.get_json(f"/agents?limit={page_size}&offset={offset}")["data"]
        items = data["affected_items"]
        agents += [normalize(a) for a in items]
        offset += len(items)
        if not items or offset >= data["total_affected_items"]:
            return agents


def normalize(agent: dict) -> dict:
    """Плоская запись агента для CSV."""
    os_info = agent.get("os", {})
    os_name = " ".join(filter(None, (os_info.get("name"), os_info.get("version")))) or "—"
    return {
        "id": agent.get("id", ""),
        "name": agent.get("name", ""),
        "ip": agent.get("ip", ""),
        "status": agent.get("status", "unknown"),
        "os": os_name,
        "version": agent.get("version", ""),
        "last_keepalive": agent.get("lastKeepAlive", ""),
    }


def write_csv(agents: list[dict], out: IO[str]) -> None:
    """Записать агентов в CSV."""
    writer = csv.DictWriter(out, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(agents)


def status_summary(agents: list[dict]) -> Counter:
    """Посчитать агентов по статусу (active, disconnected, never_connected, ...)."""
    return Counter(a["status"] for a in agents)
