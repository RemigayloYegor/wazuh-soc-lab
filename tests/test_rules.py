"""Офлайн-проверка local_rules.xml: структура и регулярки на образцах событий.

Wazuh-правила с type="pcre2" проверяются через модуль re: для используемых
конструкций (классы, группы, (?i), якоря) синтаксис PCRE2 и Python совпадает.
Финальная проверка — wazuh-logtest на менеджере (см. README).
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RULES = ET.parse(ROOT / "rules" / "local_rules.xml").getroot().findall("rule")
BY_ID = {r.get("id"): r for r in RULES}
CASES = json.loads((ROOT / "tests" / "rule_cases.json").read_text(encoding="utf-8"))


def get_field(event: dict, dotted: str):
    """Достать значение по пути вида win.eventdata.image."""
    cur = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def rule_matches(rule: ET.Element, case: dict) -> bool:
    """Упрощённая модель матчинга Wazuh: родительская группа/декодер + все field."""
    if (group := rule.findtext("if_group")) and group != case.get("group"):
        return False
    if (decoder := rule.findtext("decoded_as")) and decoder != case.get("decoder"):
        return False
    for f in rule.findall("field"):
        value = get_field(case["event"], f.get("name"))
        if value is None or not re.search(f.text, str(value)):
            return False
    return True


def test_exactly_seven_rules():
    assert len(RULES) == 7


def test_ids_unique_and_in_custom_range():
    ids = [int(r.get("id")) for r in RULES]
    assert len(ids) == len(set(ids))
    assert all(100000 <= i <= 120000 for i in ids)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get("id"))
def test_rule_has_mitre_level_description(rule):
    mitre = [e.text for e in rule.findall("mitre/id")]
    assert mitre and all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in mitre)
    assert 0 <= int(rule.get("level")) <= 15
    assert rule.findtext("description")


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.get("id"))
def test_rule_regexes_compile(rule):
    for f in rule.findall("field"):
        re.compile(f.text)


def test_brute_force_is_frequency_based():
    rule = BY_ID["100100"]
    assert int(rule.get("frequency")) >= 5
    assert rule.find("same_srcip") is not None


def test_every_rule_has_positive_and_negative_case():
    for rid in BY_ID:
        if rid == "100100":  # частотное правило проверяется только в wazuh-logtest
            continue
        expects = {c["expect"] for c in CASES if c["rule"] == rid}
        assert expects == {True, False}, f"для {rid} нужны оба типа примеров"


@pytest.mark.parametrize("case", CASES, ids=lambda c: f"{c['rule']}-{c['name']}")
def test_rule_on_sample_event(case):
    assert rule_matches(BY_ID[case["rule"]], case) is case["expect"]
