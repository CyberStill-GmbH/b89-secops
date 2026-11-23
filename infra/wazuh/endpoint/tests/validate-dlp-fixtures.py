#!/usr/bin/env python3
"""Evaluate synthetic Ferrispector JSONL events against the DLP rule fields (101110-101115).

Frequency rules (101114, 101116) need wazuh-logtest; this harness checks the base and child
field matches and the most specific rule each event should reach.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

here = Path(__file__).resolve().parent
root = ET.parse(here.parent / "rules" / "b89_endpoint_rules.xml").getroot()


def fields(rule_id: str) -> dict:
    rule = root.find(f"rule[@id='{rule_id}']")
    if rule is None:
        raise SystemExit(f"Missing DLP rule {rule_id}")
    return {field.attrib["name"]: re.compile(field.text or "") for field in rule.findall("field")}


def matches(rule_id: str, event: dict) -> bool:
    return all(pattern.search(str(event.get(name, ""))) for name, pattern in fields(rule_id).items())


def classify(event: dict) -> str:
    if matches("101110", event):
        for child in ("101112", "101111"):
            if matches(child, event):
                return child
        return "101110"
    for rule_id in ("101113", "101115"):
        if matches(rule_id, event):
            return rule_id
    return "-"


expected = [line.strip() for line in (here / "dlp-expected-rules.txt").read_text().splitlines() if line.strip()]
events = [json.loads(line) for line in (here / "dlp-cases.jsonl").read_text().splitlines() if line.strip()]
if len(events) != len(expected):
    raise SystemExit(f"Fixture count mismatch: {len(events)} events / {len(expected)} expectations")

failures = 0
for index, (event, wanted) in enumerate(zip(events, expected), start=1):
    got = classify(event)
    if got != wanted:
        failures += 1
        print(f"case {index:02d}: expected {wanted}, got {got}")
if failures:
    sys.exit(1)
print(f"PASS: {len(expected)} synthetic Ferrispector cases reach the expected DLP rule")
